#ifndef SAFEST_EXT_H_SO5EQBAM
#define SAFEST_EXT_H_SO5EQBAM
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <sstream>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <vector>
#include "latency_hash.h"
#include "generic_hash.h"
#include "message_spec.pb.h"
#include "cpp_interface.hh"

extern "C" {
#include "vivaldinode.h"
}

namespace cs {

  const std::string empty = std::string();

  /* Each CoordinateNetwork represents an individual network
   * comprised of all of the nodes that this CoordinateEngine
   * was initialized with.
   */
  struct CoordinateNetwork {
    ~CoordinateNetwork();
    torps::ext::ControlMessage prepared_response;
    std::vector<viv_instance_t* > instances;
    std::vector<std::vector<uint32_t> *> ping_targets;
    uint32_t instance_count;
  };

  class CongestionDistribution {

    public:
    CongestionDistribution(const torps::ext::CongestionProfile &spec);
    ~CongestionDistribution() {  }

    double sample();

    private:
    uint32_t bucket_count;
    uint32_t bucket_size;
    uint32_t bucket_selector[1000];
  };

  class CoordinateEngine {
  public:

    static CoordinateEngine& GetEngine()
    {
      static CoordinateEngine engine;
      return engine;
    }

    /* Service Functions*/
    void start(uint32_t port);
    int dispatch(int socket);
    void write_coordinates(int socket, uint32_t network_id);
    void prepare_response(uint32_t network_id);
    void coord_msg_from_viv_instance(torps::ext::Coordinate *,
                                     const viv_instance_t *);

    void send_response(int socket,
                      torps::ext::StatusMessage::Status s,
                      const std::string &status_msg = empty);

    /* Setup Functions */
    int initialize(const torps::ext::CoordInit & );
    int initialize_network(const torps::ext::CoordInit &,
                           CoordinateNetwork *);
    bool is_initialized();
    void cleanup(void);

    /* Engine Operation */
    int step_coordinates(uint32_t network_id);
    void pick_ping_targets(uint32_t network_id);


    /* Engine variables */
    uint32_t instance_count;
    uint32_t network_count;
    std::vector<CoordinateNetwork *> networks;
    /* This is the number of pings that each node
     * will send in an interval */
    uint32_t node_pings_per_interval;

    /* The following are variables that hold global 
     * information about the latencies and congestion
     * in the networks */
    latency_hash_t *latencies;
    inthash_t *congest_distributions;

    options_t default_opts;

    /* Utility variables */
    int _mainsock, _commsock;
    std::string msgbuf;
    struct sockaddr_in conn_addr;


  private:
    CoordinateEngine(); 
  };

}

#endif /* end of include guard: SAFEST_EXT_H_SO5EQBAM */
