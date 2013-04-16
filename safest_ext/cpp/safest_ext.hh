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
#include "message_spec.pb.h"
#include "cpp_interface.hh"

extern "C" {
#include "vivaldinode.h"
}

namespace cs {

  const std::string empty = std::string();

  class CongestionDistribution {

    public:
    CongestionDistribution(const torps::ext::NodeSpecification &spec);
    ~CongestionDistribution() { delete values; }

    double sample();

    private:
    int bucket_count;
    double * values;
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
    void write_coordinates(int socket);
    void prepare_response();
    void coord_msg_from_viv_instance(torps::ext::Coordinate *,
                                     const viv_instance_t *);

    void send_response(int socket,
                      torps::ext::StatusMessage::Status s,
                      const std::string &status_msg = empty);

    /* Setup Functions */
    int initialize(const torps::ext::CoordInit & );
    bool is_initialized();
    void cleanup(void);

    /* Engine Operation */
    int step_coordinates();
    void pick_ping_targets();


    /* Engine variables */
    uint32_t instance_count;
    viv_instance_t *instances;
    /* This is the number of pings that each node
     * will send in an interval */
    uint32_t node_pings_per_interval;
    uint32_t **ping_targets;
    double **latencies;
    CongestionDistribution ** congest_distributions;


    options_t default_opts;


    /* Utility variables */
    int _mainsock, _commsock;
    std::string msgbuf;
    struct sockaddr_in conn_addr;
    torps::ext::ControlMessage prepared_response;


  private:
    CoordinateEngine() {
      instance_count = 0;
      instances = 0;
      default_opts.VivPingUseHeight = 0;
      default_opts.VivProtectErrorWindow = 30;
      default_opts.VivProtectCentroidWindow = 30;
      default_opts.VivTimestep = 0.25;
      default_opts.VivProtectCentroidRejectRate = 0.5;
      default_opts.VivProtectErrorRejectRate = 0.5;
      default_opts.VivMemorySize = 200;
      default_opts.VivUnprotectedBootstrapCount = 200;
      default_opts.VivMaxCoordDist = 0.0;
    }
  };

}

#endif /* end of include guard: SAFEST_EXT_H_SO5EQBAM */
