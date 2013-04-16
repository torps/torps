#include "safest_ext.hh"

using namespace cs;

#define perror_quit(msg) \
  do {           \
    perror(msg); \
    exit(1);     \
  } while (0)

void 
CoordinateEngine::start( uint32_t port)
{
  int one = 1;
  int rc;

  _mainsock = socket(AF_INET,SOCK_STREAM,0);
  if (_mainsock <= 0)
    perror_quit("socket");

  fprintf(stderr,"Created socket with FD %d\n",_mainsock);

  rc = setsockopt(_mainsock,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(int));
  if (rc)
    perror_quit("setsockopt");

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  rc = bind(_mainsock,
      (struct sockaddr *)&addr, 
      sizeof(struct sockaddr_in));
  if (rc)
    perror_quit("bind");

  rc = listen(_mainsock, 5);
  if (rc)
    perror_quit("listen");

  fprintf(stderr, "Waiting for connection on %u\n", port);
  socklen_t len;
  _commsock = accept(_mainsock, (struct sockaddr *) &conn_addr, &len);

  if (!_commsock) {
    close(_mainsock);
    perror_quit("accept");
  }

  char addrbuf[64];
  fprintf(stderr,"Established connection with %s\n",
                  inet_ntop(AF_INET,&conn_addr.sin_addr,addrbuf,len));

  struct pollfd poller[2];
  poller[0].fd = _mainsock;
  poller[0].events = 0;
  poller[1].fd = _commsock;
  poller[1].events = POLLIN;

  int sock_count = 2;

  while (1) {
    if (( rc = poll( poller,sock_count, -1) ) < 0)
      perror_quit("poll");

    if (!rc)
      continue;

    /* Main socket */
    if (poller[0].revents & (POLLHUP | POLLERR)) {
      fprintf(stderr,"Error on main socket\n");
      exit(1);
    }

    if (poller[1].revents & (POLLHUP | POLLERR)) {
      fprintf(stderr,"Socket error. Dying.\n");
      exit(1);
    }
    else if (poller[1].revents & POLLNVAL) {
      fprintf(stderr,"Socket not connected\n");
      exit(1);
    } else if (poller[1].revents & POLLIN) {
      dispatch(poller[1].fd);
    } else {
      fprintf(stderr, "Poll returned unknown event\n");
    }
  }
}

size_t
read_sock(int sock, std::string &dst) 
{
  char buf[2048];
  size_t rc;

  rc = recv(sock,buf,2048,0);
  if (rc <= 0) {
    fprintf(stderr,"Failed to read from socket\n");
    return rc;
  }
  fprintf(stderr, "Read %lu bytes\n",rc);

  dst.append(buf,rc);

  return dst.length();
}

void
CoordinateEngine::send_response(int socket,
                               torps::ext::StatusMessage::Status s,
                               const std::string &status_msg)
{
  int rc;

  torps::ext::StatusMessage msg;
  if (status_msg.length() > 0) {
    msg.set_msg(status_msg);
  }
  msg.set_status(s);

  std::ostringstream obuf;
  msg.SerializeToOstream(&obuf);
  rc = send(socket,obuf.str().data(),obuf.str().size(),0);

  if (rc != msg.ByteSize())
    perror_quit("send");
}

int
CoordinateEngine::dispatch(int socket)
{
  int rc = read_sock(socket,msgbuf);

  if (rc <= 0) {
    fprintf(stderr,"Dispatched with no data to read\n");
    return rc;
  }

  torps::ext::ControlMessage msg;

  if (!msg.ParseFromString(msgbuf)) {
    fprintf(stderr, "Failed to parse valid message from stream. "
                    "May simply be incomplete thus far.\n");
    return -1;
  }
  msgbuf.clear();

  switch (msg.type()) {
    case torps::ext::INIT:
      if (!msg.has_init_data()){
        rc= -2;
        fprintf(stderr,"Message type INIT has no init_data field\n");
      }
      else {
        /* Initialize and prepare the first step */
        rc = initialize(msg.init_data());
        pick_ping_targets();
        if (step_coordinates() < 0) {
          fprintf(stderr,"Failed to step coordinates correctly\n");
          send_response(socket,torps::ext::StatusMessage::ERR,
                        "Failed to step coordinates correctly.");
        }
        prepare_response();

        send_response(socket,torps::ext::StatusMessage::OK);
      }
      break;

    case torps::ext::GET:
      send_response(socket,torps::ext::StatusMessage::DATA_NEXT);
      write_coordinates(socket);
      pick_ping_targets();
      rc = step_coordinates();
      prepare_response();
      break;

    case torps::ext::COORDS:
      rc = -1;
      fprintf(stderr, "Coordinate engine doesn't respond to COORDS");
      send_response(socket,torps::ext::StatusMessage::ERR,
                    "CoordinateEngine doesn't respond to COORDS");
      break;
  }

  return rc;
}

bool
CoordinateEngine::is_initialized()
{
  if (instance_count == 0 || instances == 0) {
    return false;
  }
  return true;
}

void
CoordinateEngine::cleanup()
{
  delete[] instances;
  for (uint32_t i = 0; i < instance_count; i++) {
    delete congest_distributions[i];
    delete[] ping_targets[i];
    delete[] latencies[i];
  }
  delete congest_distributions;
  delete[] ping_targets;
  delete[] latencies;
}

/* Initialize the coordinate engine according to the parameters 
 * in msg*/
int
CoordinateEngine::initialize(const torps::ext::CoordInit & msg)
{
  if (is_initialized()){
    cleanup();
  }
  instance_count = msg.node_data_size();
  instances = new viv_instance_t[instance_count];
  congest_distributions = new CongestionDistribution*[instance_count];

  latencies = new double*[instance_count];
  ping_targets = new uint32_t*[instance_count];
  node_pings_per_interval = msg.update_interval_seconds() / msg.ping_interval_seconds();

  for (uint32_t i = 0; i < instance_count; i++) {
    viv_instance_initialize_existing(&instances[i]);
    snprintf(instances[i].nodeid,64,"%s",msg.node_data(i).id().c_str());
    congest_distributions[i] = new CongestionDistribution(msg.node_data(i));
    ping_targets[i] = new uint32_t[node_pings_per_interval];
    latencies[i] = new double[instance_count];
  }

  for (int32_t i = 0; i < msg.latency_map_size(); i++) {
    uint32_t n1 = msg.latency_map(i).n1_idx();
    uint32_t n2 = msg.latency_map(i).n2_idx();
    assert(n1 < instance_count && n2 < instance_count);
    latencies[n1][n2] = msg.latency_map(i).latency();
    latencies[n2][n1] = msg.latency_map(i).latency();
  }

  if (!instance_count || !instances || !node_pings_per_interval) {
    return -1;
  }

  return 0;
}

void
CoordinateEngine::pick_ping_targets()
{
  fprintf(stderr,"Choosing ping targets for this round.");
  for (uint32_t i = 0; i < instance_count; i++) {
    for (uint32_t j = 0; j < node_pings_per_interval; j++) {
      uint32_t choice;
      do {
        choice = rand() % instance_count;
      } while(choice == i);

      assert(choice != i);
      ping_targets[i][j] = choice;
    }
  }
}

int
CoordinateEngine::step_coordinates()
{
  uint32_t pinging_node, target_idx, target_node;
  viv_coord_t *remote_coord;
  double remote_err;
  viv_sample_t *s;
  time_t timer;

  timer = time(0);
  for (target_idx = 0; target_idx < node_pings_per_interval; target_idx++) {
    for (pinging_node = 0; pinging_node < instance_count; pinging_node++) {

      target_node = ping_targets[pinging_node][target_idx];
      assert(target_node != pinging_node);
      fprintf(stderr,"Iteration %d of %d. Stepping node '%s' (%d of %d).\n",
                    target_idx+1, 
                    node_pings_per_interval,
                    instances[pinging_node].nodeid,
                    pinging_node+1,instance_count);

      double congestion = congest_distributions[pinging_node]->sample() +
                          congest_distributions[target_node]->sample();

      double latency = latencies[pinging_node][target_node];

      remote_coord = instances[target_node]._c;
      remote_err = instances[target_node]._pred_err;

      s = viv_record_ping_sample(&instances[pinging_node],
                                 remote_coord,
                                 latency+ congestion,
                                 remote_err,
                                 instances[target_node].nodeid);

      viv_update( &instances[pinging_node], s);

    }
  }

  fprintf(stderr,"Completed iteration in %ld seconds\n",time(0)-timer);

  return 0;
}

void
CoordinateEngine::coord_msg_from_viv_instance(
                torps::ext::Coordinate *dst,
                const viv_instance_t *instance)
{
  assert(dst);
  assert(instance);

  dst->set_node_id(instance->nodeid);
  dst->set_dim(instance->_dim);
  dst->set_error(instance->_pred_err);
  for (uint32_t i = 0; i < instance->_dim; i++) {
    dst->add_vectors(instance->_c->_v[i]);
  }
}

void
CoordinateEngine::write_coordinates(int socket)
{
  std::ostringstream outbuf;
  prepared_response.SerializeToOstream(&outbuf);

  send(socket,outbuf.str().data(),outbuf.str().size(),0);
}

void
CoordinateEngine::prepare_response()
{
  assert(is_initialized());

  torps::ext::CoordUpdate *coords = new torps::ext::CoordUpdate();
  torps::ext::Coordinate *coord;

  for (uint32_t i = 0; i < instance_count; i++) {
    coord = coords->add_coords();
    coord_msg_from_viv_instance(coord,&instances[i]);
  }

  prepared_response.set_allocated_update_data(coords);
  prepared_response.set_type(torps::ext::COORDS);
}

CongestionDistribution::CongestionDistribution(const torps::ext::NodeSpecification &spec)
{
  bucket_count = spec.congestion_dist_size();
  values = new double[bucket_count];
  for (int i = 0; i < bucket_count; i++) {
    values[i] = spec.congestion_dist(i);
  }
}

double
CongestionDistribution::sample()
{
  return values[rand() % bucket_count];
}

const options_t *
get_options()
{
  return &(cs::CoordinateEngine::GetEngine().default_opts);
}
