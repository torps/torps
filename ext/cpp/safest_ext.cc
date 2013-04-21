#include "safest_ext.hh"

using namespace cs;

#define perror_quit(msg) \
  do {           \
    perror(msg); \
    exit(1);     \
  } while (0)


CoordinateNetwork::~CoordinateNetwork()
{
  instances.erase(instances.begin(),instances.end());
}

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

  struct pollfd poller[2];
  poller[0].fd = _mainsock;
  poller[0].events = POLLIN;

  int sock_count = 1;

  while (1) {
    fprintf(stderr, "Polling on %d sockets",sock_count);
    if (( rc = poll( poller,sock_count, -1) ) < 0)
      perror_quit("poll");

    if (!rc)
      continue;

    /* Main socket */
    if (poller[0].revents & (POLLHUP | POLLERR)) {
      fprintf(stderr,"Error on main socket\n");
      exit(1);
    }
    else if (poller[0].revents & POLLIN) {
      if (sock_count == 2) {
        fprintf(stderr, "We already have aconnection \n");
        //We already have a connection
        continue;
      }
      _commsock = accept(_mainsock, (struct sockaddr *) &conn_addr, &len);

      if (!_commsock) {
        close(_mainsock);
        perror_quit("accept");
      }
      poller[1].fd = _commsock;
      poller[1].events = (POLLIN |POLLNVAL | POLLHUP | POLLERR);
      sock_count = 2;

      char addrbuf[64];
      fprintf(stderr,"Established connection with %s\n",
                      inet_ntop(AF_INET,&conn_addr.sin_addr,addrbuf,len));
      continue;
    }

    if (sock_count > 1) {
      fprintf(stderr,"Checking connected socket for data\n");

      if (poller[1].revents & (POLLHUP | POLLERR)) {
        fprintf(stderr,"Socket error. Dying.\n");
        exit(1);
      }
      else if (poller[1].revents & POLLNVAL) {
        fprintf(stderr,"Socket not connected\n");
        exit(1);
      } else if (poller[1].revents & POLLIN) {
        rc = dispatch(poller[1].fd);
        if (rc < 0) {
          perror("recv");
          break;
        }
        rc = dispatch(poller[1].fd);
        if (rc == 0) {
          sock_count = 1;
          fprintf(stderr,"Lost client connection. Listening for a new one.\n");
        }
      } else {
        fprintf(stderr, "Poll returned unknown event\n");
      }
    }
  }
}

size_t
read_sock(int sock, std::string &dst)
{
  uint32_t msglen, *intptr, rcv = 0;
  char tmpbuf[sizeof(uint32_t)];
  char buf[2048];
  int rc;

  rc = recv(sock, tmpbuf, sizeof(uint32_t), MSG_WAITALL);
  if (rc <= 0) {
    fprintf(stderr, "Failed to read message len\n");
    return rc;
  }

  intptr = (uint32_t *)tmpbuf;
  msglen = ntohl(*intptr);
  fprintf(stderr, "About to read %u byte message message\n",msglen);
  dst.clear();

  while ( rcv < msglen ) {
    rc = recv(sock,buf,2048,0);
    if (rc <= 0) {
      fprintf(stderr,"Failed to read from socket\n");
      return rc;
    }
    else {
      rcv += rc;
      fprintf(stderr, "Read %u bytes. %u remaining\n", rc,msglen - rcv);
      dst.append(buf,rc);
    }
  }

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
  // Write the message size specifier
  uint32_t msglen_n = htonl(msg.ByteSize());
  obuf.write((const char *)&msglen_n,(long)sizeof(uint32_t));
  fprintf(stderr, "Writing message of length %u\n", msg.ByteSize());

  msg.SerializeToOstream(&obuf);
  rc = send(socket,obuf.str().data(),obuf.str().size(),0);

  if (rc != (int)(msg.ByteSize() + sizeof(uint32_t)))
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
                    "May simply be incomplete thus far.\n"
                    "msgbuf has %lu bytes\n", msgbuf.length());
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
        /* Run all of the coordinate systems once */
        for (uint32_t net_idx = 0; net_idx < network_count; net_idx++) {
          pick_ping_targets(net_idx);
          if (step_coordinates(net_idx) < 0) {
            fprintf(stderr,"Failed to step coordinates correctly\n");
            send_response(socket,torps::ext::StatusMessage::ERR,
                          "Failed to step coordinates correctly.");
          }
          prepare_response(net_idx);
        }
        //Don't respond until we've initialized.
        send_response(socket,torps::ext::StatusMessage::OK, empty);

      }
      break;

    case torps::ext::GET:
      if (!msg.has_get_network_id()) {
        send_response(socket,torps::ext::StatusMessage::ERR,
                      "No network ID sent with GET request");
      }
      else {
        send_response(socket,torps::ext::StatusMessage::DATA_NEXT);
        uint32_t network_id = msg.get_network_id();
        assert(network_id < network_count);
        fprintf(stderr, "Received GET requests for network %u\n", network_id);
        write_coordinates(socket, network_id);
        pick_ping_targets(network_id);
        rc = step_coordinates(network_id);
        prepare_response(network_id);
      }
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
  if (instance_count == 0 || network_count == 0) {
    return false;
  }
  return true;
}

void
CoordinateEngine::cleanup()
{
  for (std::vector<CoordinateNetwork *>::iterator i = networks.begin();
       i != networks.end(); i++) {
    delete(*i);
  }
  networks.clear();
  inthash_clear(&congest_distributions);
  latency_hash_clear(&latencies);
}

/* Initialize a specific network instance */
int
CoordinateEngine::initialize_network(
                   const torps::ext::CoordInit & msg,
                   CoordinateNetwork *network)
{
  CongestionDistribution *tmp;
  network->instance_count = instance_count;

  for (uint32_t i = 0; i < instance_count; i++) {
    network->instances.push_back(new viv_instance_t);
    viv_instance_initialize_existing(network->instances[i]);
    snprintf(network->instances[i]->nodeid,
              64,"%s",
              msg.node_data(i).id().c_str());
    network->instances[i]->congestion_ident = 
                           msg.node_data(i).congestion_profile();

    assert(LH_OK == inthash_get(&congest_distributions,
                                network->instances[i]->congestion_ident,
                                &tmp));

    network->ping_targets.push_back(new std::vector<uint32_t>());
  }

  return 0;
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
  network_count = msg.num_networks();

  /* Load congestion profiles first so that we can error
   * check the instance congestion identifiers */
  for (int32_t i = 0; i < msg.congestion_profiles_size(); i++) {
    /* Insert Congestion Profiles keyed by their identifier */
    inthash_insert(&congest_distributions,
                   msg.congestion_profiles(i).identifier(), 
                   new CongestionDistribution(msg.congestion_profiles(i)));
  }

  for (uint32_t network = 0; network < network_count; network++) {
    networks.push_back(new CoordinateNetwork());
    initialize_network(msg, networks[network]);
  }

  node_pings_per_interval = msg.update_interval_seconds()
                                  / msg.ping_interval_seconds();


  for (int32_t i = 0; i < msg.latency_map_size(); i++) {
    uint32_t n1 = msg.latency_map(i).n1_idx();
    uint32_t n2 = msg.latency_map(i).n2_idx();
    double latency = msg.latency_map(i).latency();
    assert(n1 < instance_count && n2 < instance_count);

    /* Set n1 -> n2 */
    int rc;
    rc = latency_hash_insert(&latencies,n1,n2,latency);
    if (rc == LH_DUP_INSERT) {
      fprintf(stderr,"Attempted to insert duplicate latency for %u -> %u",
              n1,n2);
    }

    rc = latency_hash_insert(&latencies,n2,n1,latency);
    if (rc == LH_DUP_INSERT) {
      fprintf(stderr,"Attempted to insert duplicate latency for %u -> %u",
              n1,n2);
    }
  }

  if (!instance_count || networks.empty() || !node_pings_per_interval) {
    return -1;
  }

  fprintf(stderr, "Initialized CoordinateEngine with %u networks.\n"
                  "Each network has %u instances. Nodes will ping %u "
                  "times per interval.\n",
                  network_count, instance_count, node_pings_per_interval);

  return 0;
}

void
CoordinateEngine::pick_ping_targets(uint32_t network_id)
{
//#error theres a bug here
  CoordinateNetwork *network = networks[network_id];
  std::vector<uint32_t> *targetList;
  fprintf(stderr,"Choosing ping targets for this round.");
  for (uint32_t i = 0; i < instance_count; i++) {
    targetList = network->ping_targets[i];
    targetList->clear();

    for (uint32_t j = 0; j < node_pings_per_interval; j++) {
      uint32_t choice;
      do {
        choice = rand() % instance_count;
      } while(choice == i);

      assert(choice != i);
      targetList->push_back(choice);
    }
  }
}

int
CoordinateEngine::step_coordinates(uint32_t network_id)
{
  uint32_t pinging_node, target_idx, target_node;
  int rc;
  viv_instance_t *pinging_instance, *target_instance;
  viv_coord_t *remote_coord;
  double remote_err;
  viv_sample_t *s;
  time_t timer;
  CoordinateNetwork *network = networks[network_id];

  timer = time(0);
  for (target_idx = 0; target_idx < node_pings_per_interval; target_idx++) {
    for (pinging_node = 0; pinging_node < instance_count; pinging_node++) {

      target_node = network->ping_targets[pinging_node]->at(target_idx);
      assert(target_node != pinging_node);
      assert(target_node < instance_count);

      pinging_instance = network->instances[pinging_node];
      target_instance = network->instances[target_node];

      fprintf(stderr,"Iteration %d of %d. Stepping node '%s' (%d of %d).\n",
                    target_idx+1,
                    node_pings_per_interval,
                    pinging_instance->nodeid,
                    pinging_node+1,instance_count);

      CongestionDistribution * cdist;
      double congestion =0.0;

      rc = inthash_get(&congest_distributions,pinging_instance->congestion_ident,&cdist);
      assert(rc == LH_OK);
      congestion += cdist->sample();
      rc = inthash_get(&congest_distributions,target_instance->congestion_ident,&cdist);
      assert(rc == LH_OK);
      congestion += cdist->sample();

      double latency;
      rc = latency_hash_get(&latencies,pinging_node,target_node, &latency);
      assert(rc == LH_OK);

      remote_coord = target_instance->_c;
      remote_err = target_instance->_pred_err;

      s = viv_record_ping_sample(pinging_instance,
                                 remote_coord,
                                 latency+ congestion,
                                 remote_err,
                                 target_instance->nodeid);

      viv_update( pinging_instance, s);

    }
  }

  fprintf(stderr,"Completed iteration in %ld seconds\n",time(0)-timer);

  return 1; // ok
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
CoordinateEngine::write_coordinates(int socket,uint32_t network_id)
{
  std::ostringstream outbuf;
  torps::ext::ControlMessage *msg = &(networks[network_id]->prepared_response);

  uint32_t msglen_n = htonl(msg->ByteSize());
  outbuf.write((const char *)&msglen_n,(long)sizeof(uint32_t));
  fprintf(stderr, "Writing message of length %u\n",msg->ByteSize());

  msg->SerializeToOstream(&outbuf);

  send(socket,outbuf.str().data(),outbuf.str().size(),0);
}

void
CoordinateEngine::prepare_response(uint32_t network_id)
{
  assert(is_initialized());
  CoordinateNetwork *network = networks[network_id];

  torps::ext::CoordUpdate *coords = new torps::ext::CoordUpdate();
  torps::ext::Coordinate *coord;
  coords->set_network_id(network_id);

  for (uint32_t i = 0; i < instance_count; i++) {
    coord = coords->add_coords();
    coord_msg_from_viv_instance(coord,network->instances[i]);
  }

  network->prepared_response.set_allocated_update_data(coords);
  network->prepared_response.set_type(torps::ext::COORDS);
}

CongestionDistribution::CongestionDistribution(const torps::ext::CongestionProfile &spec)
{
  bucket_size = spec.binsize();
  bucket_count = spec.binprobs_size();

  uint32_t bin_iter = 0, bin_start = 0;
  for (uint32_t i = 0; i < bucket_count; i++){
    /* Each element in binprobs represents the probability
     * of selecting that bin for congestion purposes.
     * We're going to represent that at the granularity of 
     * .000's by inserting a number into each of our 1000
     * bins that represents what bin you should be in if you
     * draw a random number from [0,1000].
     */
    uint32_t num_assigned_buckets = 1000 * spec.binprobs(i);
    fprintf(stderr,"Assigning %.2f-%.2f probability of %d/1000\n",
            (double)i*bucket_size,
            ((double)((i+1)*bucket_size)) - .01,
            num_assigned_buckets);

    for (bin_iter = bin_start ; bin_iter - bin_start < num_assigned_buckets; bin_iter++) {
      if (bin_iter == 1000) 
        break;
      bucket_selector[bin_iter] = i;
    }
    bin_start = bin_iter;

    if (bin_iter == 1000)
      assert(i == bucket_count - 1);
  }
}

double
CongestionDistribution::sample()
{
  uint32_t selected_bin = bucket_selector[rand() % bucket_count];
  assert(selected_bin <= bucket_count);

  uint32_t random_in_range = rand() % (bucket_size * 1000);
  double double_in_range = ((double)random_in_range) / 1000.0;
   
  return ((double)(bucket_size * selected_bin))  // offset to bucket
         + double_in_range;                      // offset inside bucket
}

CoordinateEngine::CoordinateEngine()
{
  instance_count = 0;
  network_count = 0;
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

const options_t *
get_options()
{
  return &(cs::CoordinateEngine::GetEngine().default_opts);
}
