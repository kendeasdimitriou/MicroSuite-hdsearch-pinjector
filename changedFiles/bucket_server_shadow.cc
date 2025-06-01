/* Author: Akshitha Sriraman
   Ph.D. Candidate at the University of Michigan - Ann Arbor*/
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <memory>
#include <omp.h>
#include <string>
#include <sys/time.h>
#include <fstream>
#include <thread>
#include <grpc++/grpc++.h>
#include "bucket_service/service/helper_files/server_helper.h"
#include "bucket_service/service/helper_files/timing.h"
#include "bucket_service/src/utils.h"
#include <pthread.h>

using grpc::Server;
using grpc::ServerAsyncResponseWriter;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCompletionQueue;
using grpc::Status;
using bucket::DataPoint;
using bucket::MultipleDataPoints;
using bucket::PointIdList;
using bucket::NearestNeighborRequest;
using bucket::TimingDataInMicro;
using bucket::NearestNeighborResponse;
using bucket::DistanceService;

/* Make dataset a global, so that the dataset can be loaded
   even before the server starts running. */
MultiplePoints dataset;

std::string ip_port = "";
unsigned int bucket_parallelism = 0;

int num_cores = 0, bucket_server_num = 0, num_bucket_servers = 0;
//static std::atomic<uint64_t> g_shadow_id_counter{0};

std::atomic<bool> shadowDone{false};
thread_local bool isShadow = false;

extern "C" {

void FaultInjectionBegin() {
    std::ofstream file("fault_injection.log", std::ios::app);
    if (file.is_open()) {
        file << "fault injection started" << std::endl;
    }
}

void FaultInjectionEnd() {
    std::ofstream file("fault_injection.log", std::ios::app);
    if (file.is_open()) {
        file << "fault injection finished" << std::endl;
    }
}

void FaultInjectionBegin_parent() {
    std::ofstream file("fault_injection.log", std::ios::app);
    if (file.is_open()) {
        file << "fault injection started" << std::endl;
    }
}

void FaultInjectionEnd_parent() {
    std::ofstream file("fault_injection.log", std::ios::app);
    if (file.is_open()) {
        file << "fault injection finished" << std::endl;
    }
}
void QueryBegins(int queryId) {
    std::ofstream file("query_begins.log", std::ios::app);
    if (file.is_open()) {
        file << "Query Begins" << std::endl;
    //uint64_t value = request.queries(0);
        file << queryId << std::endl;
  }
}
} // extern "C"



void ProcessRequest(NearestNeighborRequest &request,
        NearestNeighborResponse* reply)
{
uint64_t value = request.queries(0);
int intValue = static_cast<int>(value);
//FaultInjectionBegin_parent();
QueryBegins(intValue);
FaultInjectionBegin();
//    TwoThreadBarrier barrier;
    /* If the index server is asking for util info,
       it means the time period has expired, so
       the bucket must read /proc/stat to provide user, system, io, and idle times.*/
    if(request.util_request().util_request())
    {
        uint64_t user_time = 0, system_time = 0, io_time = 0, idle_time = 0;
        GetCpuTimes(&user_time,
                &system_time,
                &io_time,
                &idle_time);
        reply->mutable_util_response()->set_user_time(user_time);
        reply->mutable_util_response()->set_system_time(system_time);
        reply->mutable_util_response()->set_io_time(io_time);
        reply->mutable_util_response()->set_idle_time(idle_time);
        reply->mutable_util_response()->set_util_present(true);
    }

    /* Simply copy request id into the reply - this was just a
       piggyback message.*/
    reply->set_request_id(request.request_id());

    /* Get the current idle time and total time
       so as to calculate the CPU util when the bucket is done.*/
    size_t idle_time_initial = 0, total_time_initial = 0, idle_time_final = 0, total_time_final = 0;
    //GetCpuTimes(&idle_time_initial, &total_time_initial);

    // Unpack received queries and point IDs
//std::cout << "Request fields: " << request.DebugString() << std::endl;
    Point p(dataset.GetPointAtIndex(0).GetSize(), 0.0);
    MultiplePoints queries(request.queries_size(), p);
    std::vector<std::vector<uint32_t>> point_ids_vec;
    uint32_t bucket_server_id, shard_size;
    uint64_t start_time, end_time;
    start_time = GetTimeInMicro();
    UnpackBucketServiceRequestAsync(request,
            dataset,
            &queries,
            &point_ids_vec,
            &bucket_server_id,
            &shard_size,
            reply);
    end_time = GetTimeInMicro();
//std::cout << "Request fields: " << request.DebugString() << std::endl;
    reply->mutable_timing_data_in_micro()->set_unpack_bucket_req_time_in_micro((end_time - start_time));
    /* Next piggy back message - sent the received query back to the
       index server. Helps to merge async responses.*/
    // Remove duplicate point IDs.
    //RemoveDuplicatePointIDs(point_ids_vec);

    // Dataset dimension must be equal to queries dimension.
#if 0
    dataset.ValidateDimensions(dataset.GetPointDimension(),
            queries.GetPointDimension());
#endif

    // Calculate the top K distances for all queries.
    DistCalc knn_answer;
    uint32_t number_of_nearest_neighbors = (uint32_t)request.requested_neighbor_count();
    start_time = GetTimeInMicro();
    CalculateKNN(queries,
                 dataset,
                 point_ids_vec,
                 number_of_nearest_neighbors,
                 num_cores,
                 &knn_answer);
    end_time = GetTimeInMicro();
    reply->mutable_timing_data_in_micro()->set_calculate_knn_time_in_micro((end_time - start_time));

    // Convert K-NN into form suitable for GRPC.
    start_time = GetTimeInMicro();

    PackBucketServiceResponse(knn_answer,
            bucket_server_id,
            shard_size,
            reply);

    end_time = GetTimeInMicro();
    reply->mutable_timing_data_in_micro()->set_pack_bucket_resp_time_in_micro((end_time - start_time));
    //GetCpuTimes(&idle_time_final, &total_time_final);
    const float idle_time_delta = idle_time_final - idle_time_initial;
    const float total_time_delta = total_time_final - total_time_initial;
    const float cpu_util = (100.0 * (1.0 - (idle_time_delta/total_time_delta)));
    reply->mutable_timing_data_in_micro()->set_cpu_util(cpu_util);
    reply->set_index_view(request.index_view());

  // Determine thread-specific filename: knn_answer_<threadid>.txt
    //auto tid = std::this_thread::get_id();
   // auto tid_hash = std::hash<std::thread::id>{}(tid);

    std::ostringstream fname;
    fname << "knn_answer_.txt";

    // Serialize the knn_answer stored in reply to file
    std::ofstream ofs(fname.str(), std::ios::app);
    if (ofs.is_open()) {
        // Assuming reply contains a DebugString method for human-readable output
        ofs << knn_answer.get_knn_value()<<(isShadow ? " SHDW" : " MAIN")<<'\n';
        ofs.close();
    } else {
        fprintf(stderr, "Failed to open file %s for writing knn_answer\n", fname.str().c_str());
    }
  //  barrier.wait();
FaultInjectionEnd();
}











//-----------------------------------





extern "C" {



//static std::atomic<uint64_t> g_shadow_id_counter{0};
// ------------------- 1. State for shadow processing -------------------
struct ShadowState {
    NearestNeighborRequest*  req;
    NearestNeighborResponse* rep;
};

// ------------------- 2. Deep-copy the state -------------------
static ShadowState* clone_state(const NearestNeighborRequest& orig_req,
                                const NearestNeighborResponse& orig_rep_template)
{
    //g_shadow_id_counter.fetch_add(1, std::memory_order_relaxed);
    ShadowState* st = (ShadowState*)malloc(sizeof(*st));
    if (!st) return nullptr;

    // Use protobuf copy constructors for deep copies
    st->req = new NearestNeighborRequest(orig_req);
    st->rep = new NearestNeighborResponse(orig_rep_template);

    return st;
}

// ------------------- 3. Thread entry point for shadow execution -------------------
static void* shadow_entry(ShadowState* st) {
//    ShadowState* st = (ShadowState*)arg;
   printf("shdow in\n");
   isShadow=true;
    // Execute ProcessRequest on the copied inputs
    ProcessRequest(*st->req, st->rep);
   printf("shdow out\n");

    // Here you can handle st->rep as needed (e.g., logging, metrics, custom sending)

    // Clean up allocated memory
    delete st->req;
    delete st->rep;
    free(st);
    shadowDone.store(true, std::memory_order_release);
    pthread_exit(nullptr);
    return nullptr;
}

// ------------------- 4. Public API to launch shadow execution -------------------
int StartShadowProcessRequest(const NearestNeighborRequest& request,
                              const NearestNeighborResponse& reply_template)
{
    // Clone the inputs for isolated execution
    ShadowState* st = clone_state(request, reply_template);
    if (!st) {
        perror("clone_state failed");
        return -1;
    }

    // Create a detached thread

  // Launch a detached C++ thread
    try {
        std::thread([st]{ shadow_entry(st); }).detach();
    } catch (const std::system_error& e) {
        fprintf(stderr, "Failed to create shadow thread: %s\n", e.what());
        delete st->req;
        delete st->rep;
        free(st);
        return -1;
    }

    // Detached thread; no join needed
    return 0;
}


///---------------------------------------
}













// Logic and data behind the server's behavior.
class ServiceImpl final {
    public:
        ~ServiceImpl() {
            server_->Shutdown();
            // Always shutdown the completion queue after the server.
            cq_->Shutdown();
        }
        // There is no shutdown handling in this code.
        void Run() {
            std::string server_address(ip_port);
            ServerBuilder builder;
            // Listen on the given address without any authentication mechanism.
            try
            {
                builder.AddListeningPort(server_address,
                        grpc::InsecureServerCredentials());
            } catch(...) {
                CHECK(false, "ERROR: Enter a valid IP address follwed by port number - IP:Port number\n");
            }
            // Register "service_" as the instance through which we'll communicate with
            // clients. In this case it corresponds to an *asynchronous* service.
            builder.RegisterService(&service_);
            // Get hold of the completion queue used for the asynchronous communication
            // with the gRPC runtime.
            cq_ = builder.AddCompletionQueue();
            // Finally assemble the server.
            server_ = builder.BuildAndStart();
            std::cout << "Server listening on " << server_address << std::endl;
            // Proceed to the server's main loop.
            if (bucket_parallelism == 1) {
                HandleRpcs();
            }
            omp_set_dynamic(0);
            omp_set_num_threads(bucket_parallelism);
            omp_set_nested(2);
#pragma omp parallel
            {
                HandleRpcs();
            }
        }
    private:
        // Class encompasing the state and logic needed to serve a request.
        class CallData {
            public:
                // Take in the "service" instance (in this case representing an asynchronous
                // server) and the completion queue "cq" used for asynchronous communication
                // with the gRPC runtime.
                CallData(DistanceService::AsyncService* service, ServerCompletionQueue* cq)
                    : service_(service), cq_(cq), responder_(&ctx_), status_(CREATE) {
                        // Invoke the serving logic right away.
                        Proceed();
                    }

                void Proceed() {
                    if (status_ == CREATE) {
                        // Make this instance progress to the PROCESS state.
                        status_ = PROCESS;

                        // As part of the initial CREATE state, we *request* that the system
                        // start processing requests. In this request, "this" acts are
                        // the tag uniquely identifying the request (so that different CallData
                        // instances can serve different requests concurrently), in this case
                        // the memory address of this CallData instance.
                        service_->RequestGetNearestNeighbors(&ctx_, &request_, &responder_, cq_, cq_,
                                this);
                    } else if (status_ == PROCESS) {
                        // Spawn a new CallData instance to serve new clients while we process
                        // the one for this CallData. The instance will deallocate itself as
                        // part of its FINISH state.
                        new CallData(service_, cq_);
    shadowDone.store(false, std::memory_order_release);
                        // The actual processing.
                   if (StartShadowProcessRequest(request_, reply_) < 0) {
                        fprintf(stderr, "Failed to launch shadow ProcessRequest\n");
                    }

    // busy-wait loop με λίγο sleep για να μην κάψει 100% CPU
    while (!shadowDone.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }


                        ProcessRequest(request_, &reply_);

                    // Shadow execution (non-blocking, isolated)
   //                if (StartShadowProcessRequest(request_, reply_) < 0) {
  //                      fprintf(stderr, "Failed to launch shadow ProcessRequest\n");
//                    }

                //   EndOfQuery(request_);
                        // And we are done! Let the gRPC runtime know we've finished, using the
                        // memory address of this instance as the uniquely identifying tag for
                        // the event.
                        status_ = FINISH;
                        responder_.Finish(reply_, Status::OK, this);
                    } else {
                        //GPR_ASSERT(status_ == FINISH);
                        // Once in the FINISH state, deallocate ourselves (CallData).
                        delete this;
                    }
                }
            private:
                // The means of communication with the gRPC runtime for an asynchronous
                // server.
                DistanceService::AsyncService* service_;
                // The producer-consumer queue where for asynchronous server notifications.
                ServerCompletionQueue* cq_;
                // Context for the rpc, allowing to tweak aspects of it such as the use
                // of compression, authentication, as well as to send metadata back to the
                // client.
                ServerContext ctx_;

                // What we get from the client.
                NearestNeighborRequest request_;
                // What we send back to the client.
                NearestNeighborResponse reply_;

                // The means to get back to the client.
                ServerAsyncResponseWriter<NearestNeighborResponse> responder_;

                // Let's implement a tiny state machine with the following states.
                enum CallStatus { CREATE, PROCESS, FINISH };
                CallStatus status_;  // The current serving state.
        };

        // This can be run in multiple threads if needed.
        void HandleRpcs() {
            // Spawn a new CallData instance to serve new clients.
            new CallData(&service_, cq_.get());
            void* tag;  // uniquely identifies a request.
            bool ok;
            while (true) {
                // Block waiting to read the next event from the completion queue. The
                // event is uniquely identified by its tag, which in this case is the
                // memory address of a CallData instance.
                // The return value of Next should always be checked. This return value
                // tells us whether there is any kind of event or cq_ is shutting down.
                //GPR_ASSERT(cq_->Next(&tag, &ok));
                cq_->Next(&tag, &ok);
                /*auto r = cq_->AsyncNext(&tag, &ok, gpr_time_0(GPR_CLOCK_REALTIME));
                  if (r == ServerCompletionQueue::GOT_EVENT) {
                //GPR_ASSERT(ok);
                static_cast<CallData*>(tag)->Proceed();
                }
                if (r == ServerCompletionQueue::TIMEOUT) continue;*/
                //GPR_ASSERT(ok);
                static_cast<CallData*>(tag)->Proceed();
            }
        }

        std::unique_ptr<ServerCompletionQueue> cq_;
        DistanceService::AsyncService service_;
        std::unique_ptr<Server> server_;
};
/*
std::string get_and_remove_first_ip(const std::string& filename) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        throw std::runtime_error("Could not open " + filename);
    }

    std::string first_line;
    std::vector<std::string> remaining_lines;
    bool first = true;

    std::string line;
    while (std::getline(infile, line)) {
        if (first) {
            first_line = line;
            first = false;
        } else {
            remaining_lines.push_back(line);
        }
    }
    infile.close();

    if (first_line.empty()) {
        throw std::runtime_error("IP list is empty!");
    }
    std::ofstream outfile(filename, std::ios::trunc);
    for (const auto& l : remaining_lines) {
        outfile << l << "\n";
    }
   outfile.close();

    return first_line;
}
*/
int main(int argc, char** argv) {
    std::string dataset_file_name;
    if (argc == 7) {
        try
        {
            dataset_file_name = argv[1];
        }
        catch(...)
        {
            CHECK(false, "Enter a valid string for dataset file path\n");
        }
    } else {
        CHECK(false, "Format: ./<bucket_server> <dataset file path> <IP address:Port Number> <Mode 1 - read dataset from text file OR Mode 2 - read dataset from binary file <number of bucket server threads> <num of cores: -1 if you want all cores on the machine> <bucket server number> <number of bucket servers in the system>\n");
    }
    // Load the bucket server IP
    ip_port = argv[2];
  //  try {
   //     ip_port = get_and_remove_first_ip("ip_List.txt");
    //    std::cout << "Using IP:PORT = " << ip_port << std::endl;

      // ./bucket_server ip_port ...

  //  } catch (const std::exception& e) {
   //     std::cerr << "Error: " << e.what() << std::endl;
    //    return 1;
   // }
    // Create dataset.
    int mode = atoi(argv[3]);

    num_cores = atoi(argv[4]);

    if ( (num_cores == -1) || (num_cores > GetNumProcs()) ) {
        num_cores = GetNumProcs();
    }

    bucket_parallelism = num_cores;
    bucket_server_num = atoi(argv[5]);
    num_bucket_servers = atoi(argv[6]);
//FaultInjectionBegin_parent();
    if (mode == 1)
    {
        CreatePointsFromFile(dataset_file_name, &dataset);
    } else if (mode == 2) {
        CreateDatasetFromBinaryFile(dataset_file_name,
                bucket_server_num,
                num_bucket_servers,
                &dataset);
    } else {
        CHECK(false, "ERROR: Argument 3 - Mode can either be 1 (text file) or 2 (binary file\n");
    }
//FaultInjectionEnd_parent();
    ServiceImpl server;
    server.Run();
    return 0;
}
