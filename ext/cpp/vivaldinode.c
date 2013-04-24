#ifdef __cplusplus
extern "C" {
#endif

#include "vivaldinode.h"
#include <string.h>
#include "tor_stubs.h"
#undef log
#include <math.h>


viv_instance_t *my_vivaldi;

#define smartlist_insert_sample(sl,pos,sample) \
  do { \
    sample->__refct++; \
    smartlist_insert((sl),(pos),(sample)); \
  } while (0)

#define smartlist_pop_last_sample(sl) \
  do { \
    viv_sample_t *old = (viv_sample_t *)smartlist_pop_last((sl));  \
    if ((--(old->__refct)) <= 0)                    \
      viv_sample_free(old);                          \
  } while (0)

/** How many samples should we receive before adjusting our coordinate. */
#define VIV_BOOTSTRAP_PERIOD 15

/** The Vivaldi error constant **/
#define VIV_ERROR_CONSTANT 0.05

/** This is a multiplier of the force to be applied to our coordinates.
 *  On pages 20 of the Vivaldi paper, they note that empirically a constant C_c
 *  of 0.25 yielded the best results
 */
#define REL_REL_TIMESTEP 0.25

/** Memcpy an object of type <b>type</b> from <b>src</b>
 * into <b>buf</b> at <b>offset</b>.
 *
 * Type conversions will take place using standard C rules,
 * so don't go crazy.
 **/
#define memcpy_type(type,src,buf,offset) \
  do {                   \
    type ___tmp = (src); \
    memcpy((buf) + (offset), &(___tmp), sizeof(type)); \
    (offset) += sizeof(type); \
  } while (0)

/** A Vivaldi sample from a remote node, including
 * the remote node's coordinate, the empirical latency
 * and the remote node's predicted error.
 **/
struct VIV_SAMPLE {
    viv_coord_t *_c;
    double _latency;
    double _error;
    int32_t __refct;
};

//PROTECTED FUNCTION PROTOTYPES
/** Creates a new Vivaldi sample **/
static viv_sample_t *viv_sample_init( viv_coord_t *c, double l, double e );
static void viv_sample_free( viv_sample_t *sample );

static void viv_minus( viv_coord_t *a, viv_coord_t *b, viv_coord_t *result );
static void viv_plus( viv_coord_t *a, viv_coord_t *b, viv_coord_t *result );
static void viv_divide( viv_coord_t *c, double x );
static void viv_multiply_by_x( viv_coord_t *c, double x );
#if 0
static double viv_multiply( viv_coord_t *a, viv_coord_t *b);
#endif
void viv_clone( viv_coord_t *dest, viv_coord_t *source );

char viv_should_update( viv_instance_t *node, viv_coord_t *new_coord );
static char viv_prot_error_check(viv_instance_t *node, viv_coord_t *new_coord );
static char viv_prot_centroid_check(viv_instance_t *node, viv_sample_t *s);
static void viv_prot_update_buffers(viv_instance_t *node, viv_sample_t *sample);

static void update_stability(viv_instance_t *node,double change);
static inline int sl_double_compare(const void **a, const void **b);

static inline int safe_isnan(double *d);

/** Creates and returns a new Vivaldi coordinate with <b>dimensions</b> dimensions,
 * and all elements initialized to zero.
 */
viv_coord_t *
viv_coord_init( )
{
  viv_coord_t *coord = (viv_coord_t *)tor_malloc(sizeof(viv_coord_t));
  uint8_t i;
  for (i = 0; i < VIV_DIMENSIONS; i++)
  {
    coord->_v[i] = 0.0;
  }
  coord->_dimensions = VIV_DIMENSIONS;
  coord->_ht = 0.0;
  return coord;
}

/** Free a Viv_Coord object **/
void
viv_coord_free( viv_coord_t *coord )
{
  _tor_free( coord );
}

uint32_t viv_coord_equal(const viv_coord_t *c1,
                         const viv_coord_t *c2)
{
  int i;

  if (c1->_dimensions != c2->_dimensions)
    return 0;
  for (i = 0; i < c1->_dimensions; i++) {
    if (c1->_v[i] != c2->_v[i])
      return 0;
  }

  return 1;
}

const viv_coord_t *
viv_info_get_coord(const viv_coord_info_t *ci)
{
  if (!ci)
    return NULL;
  return &(ci->coord);
}

/** Given a remote coordinate <b>c</b>, remote error <b>e</b>,
 * and remote error <b>e</b>, create and return a Viv_Sample
 * object containing those elements.
 */
viv_sample_t *viv_sample_init( viv_coord_t *c, double l, double e)
{
  tor_assert( c );
  viv_sample_t *sample = (viv_sample_t*)tor_malloc(sizeof(viv_sample_t));
  viv_coord_t *coord = viv_coord_init();
  viv_clone( coord, c );
  sample->_c = coord;
  sample->_latency = l;
  sample->_error = e;
  sample->__refct = 0;
  return sample;
}

/** Free a Viv_Sample object **/
void
viv_sample_free( viv_sample_t *sample )
{
  if ((--(sample->__refct)) > 0)
    return;
  tor_free( sample->_c );
  tor_free( sample );
}


void viv_node_free( viv_instance_t *node )
{
  SMARTLIST_FOREACH(node->_memory,viv_sample_t*,s,
      {
      viv_sample_free(s);
      });
  smartlist_free(node->_memory);
  SMARTLIST_FOREACH(node->prot_err_window,viv_sample_t*,s,
      {
      viv_sample_free(s);
      });
  smartlist_free(node->prot_err_window);
  SMARTLIST_FOREACH(node->prot_centroid_window,viv_sample_t*,s,
      {
      viv_sample_free(s);
      });
  smartlist_free(node->prot_centroid_window);

  tor_free( node );
}

double viv_flatearth_dist(const viv_coord_t *a, const viv_coord_t *b)
{

  double d = 0.0;
  tor_assert (a->_dimensions == b->_dimensions );
  uint8_t i;
  for (i = 0; i < a->_dimensions; i++)
    d += (a->_v[i] - b->_v[i])*(a->_v[i] - b->_v[i]);
  d = sqrt(d);
  if (get_options()->VivPingUseHeight)
    d += a->_ht + b->_ht;
  return d;
}

double viv_dist( const viv_coord_t *a, const viv_coord_t *b)
{
  return viv_flatearth_dist (a, b);
}

/** Calculate the weight for this sample **/
static inline double
viv_calc_weight(viv_instance_t *node, viv_sample_t *sample)
{
  return node->_pred_err / (node->_pred_err + sample->_error);
}


/** Update what we believe to be our local error based on the recently
 *  received sample. Return the weight value for this sample.
 **/
double viv_update_error( viv_instance_t *node, viv_sample_t *sample )
{
  double sample_weight = node->_pred_err / (node->_pred_err + sample->_error);
  double expect = viv_dist (node->_c, sample->_c);
  double actual = sample->_latency;
  double constant = VIV_ERROR_CONSTANT;

  if (actual <= 0)
  {
    log_notice(LD_GENERAL, "Did not update coordinate error because "
                           "received sample latency of zero.");
    return 0;
  }

  double rel_error = fabs(expect - actual)/actual;

  //ei = es ×ce ×w+ei ×(1−ce ×w)
  double method2 = rel_error * constant * sample_weight
                   + node->_pred_err * (1 - constant * sample_weight);

  if (node->_pred_err < 0)
  {
    node->_pred_err = rel_error;
  } else if (sample->_error < 0)
  {
    //  _pred_err = _pred_err;
  } else {
    double ce = node->_pred_err * node->_pred_err;
    double he = sample->_error * sample->_error;
    double new_pred_err = rel_error*(ce/(he + ce)) + node->_pred_err*(he/(he + ce));
    node->_pred_err = (19*node->_pred_err + new_pred_err)/20.0;
    if (node->_pred_err > 1.0)
    {
      node->_pred_err = 1.0;
    }
  }

  log_notice(LD_GENERAL,
              "Computed new predictive error as: %0.4f. Paper method computes it as %0.4f",
              node->_pred_err, method2);

  return sample_weight;
}

double viv_length( viv_coord_t *c )
{

  double l = 0.0;
  uint8_t i;
  for (i = 0; i < c->_dimensions; i++)
  {
    l += c->_v[i] * c->_v[i];
  }
  l = sqrt(l);
  if (get_options()->VivPingUseHeight)
  {
    l += c->_ht;
  }
  return l;
}

double viv_plane_length( viv_coord_t *c )
{
  double l = 0.0;
  uint8_t i;
  for (i = 0; i < c->_dimensions; i++)
  {
    l += c->_v[i] * c->_v[i];
  }
  l = sqrt(l);
  return l;
}

/** From the Vivaldi paper, subtraction is:
 *
 * [x,xh]−[y,yh] = [(x−y),xh + yh]
 **/
void viv_minus( viv_coord_t *a, viv_coord_t *b, viv_coord_t *result )
{
  uint8_t i;
  assert (a->_dimensions == b->_dimensions);
  for (i = 0; i < a->_dimensions; i++)
    result->_v[i] = a->_v[i] - b->_v[i];
  if (get_options()->VivPingUseHeight)
    result->_ht = a->_ht + b->_ht;
}

void viv_plus( viv_coord_t *a, viv_coord_t *b, viv_coord_t *result )
{
  uint8_t i;
  assert (a->_dimensions == b->_dimensions);
  for (i = 0; i < a->_dimensions; i++)
    result->_v[i] = a->_v[i] + b->_v[i];
  if (get_options()->VivPingUseHeight)
    result->_ht = a->_ht + b->_ht;
}

void viv_divide( viv_coord_t *c, double x )
{
  uint8_t i;
  for (i = 0; i < c->_dimensions; i++)
    c->_v[i] /= x;
  if (get_options()->VivPingUseHeight)
    c->_ht /= x;
}

/** The Vivaldi paper defines multiply as:
 * a*[x,xh] = [a*x,a*xh]
 **/
void viv_multiply_by_x( viv_coord_t *c, double x )
{
  uint8_t i;
  for (i = 0; i < c->_dimensions; i++)
    c->_v[i] *= x;
  if (get_options()->VivPingUseHeight)
    c->_ht *= x;
}

#if 0
double viv_multiply( viv_coord_t *a, viv_coord_t *b)
{
  uint8_t i;
  assert (a->_dimensions == b->_dimensions);
  double ret = 0.0;
  for (i = 0; i < a->_dimensions; i++)
    ret += a->_v[i] * b->_v[i];
  return ret;
}
#endif

/** Clone the viv_coord_t <b>source</b> to <b>dest</b>. **/
void
viv_clone( viv_coord_t *dest, viv_coord_t *source )
{
  uint8_t i;
  dest->_dimensions = source->_dimensions;
  for (i = 0; i < VIV_DIMENSIONS; i++)
    dest->_v[i] = source->_v[i];
  dest->_ht = source->_ht;
}

/** Calculates the variance of a smartlist of doubles <b>values</b>, and
 * returns the result.
 **/
double
smartlist_variance_double(smartlist_t *values)
{

  int n = 0;
  double oldM = 0.0,newM = 0.0,oldS = 0.0,newS = 0.0;
  oldS = 0.0;
  /** Debug Start **/
  //char * debug_msg = malloc(sizeof(char)* 256);
  //int offset = 0;
  /** Debug End **/

  SMARTLIST_FOREACH(values, double*,value,
      {
      n++;
      /** Debug Code Start **/
      //  offset += snprintf(debug_msg + offset, 256-offset, " %.2f", *value);
      /** Debug Code End **/
      if (n == 1)
{
      oldM = newM = *value;
      oldS = 0.0;
      } else {
      newM = oldM + (*value - oldM)/n;
      newS = oldS + (*value - oldM)*(*value - newM);

      oldM = newM;
      oldS = newS;
      }
      });

  /** Debug Code Start **/
  //snprintf(debug_msg +offset, 256-offset, " Variance: %.2f", ((n > 1) ? newS / (n-1) : 0.0));
  //log_notice(LD_GENERAL, "Variance Calc: %s", debug_msg);
  /** Debug Code End **/
  return ( (n > 1) ? newS / (n-1) : 0.0);
}


#define smartlist_stddev_double(smlist) \
  sqrt(smartlist_variance_double(smlist))

viv_coord_t *
viv_net_force( viv_instance_t *node, viv_sample_t *sample, double weight)
{
  viv_coord_t *f = viv_coord_init( );

  double actual = sample->_latency;
  double expect = viv_dist(node->_c, sample->_c);

  if (actual >= 0)
  {
    double grad = expect - actual;
    viv_coord_t *dir = viv_coord_init( );
    viv_minus( sample->_c, node->_c, dir );
    double l = viv_length(dir);
    while (viv_plane_length(dir) < 1.0)
    { //nodes are on top of one another
      uint8_t j;
      for (j = 0; j < dir->_dimensions; j++) //choose a random direction
        dir->_v[j] += (double)(crypto_rand_uint64(10) - 5) / 10.0;
      if (get_options()->VivPingUseHeight)
        dir->_ht += (double)(crypto_rand_uint64(10)) / 10.0;
      l = viv_length (dir);
    }
    double unit = 1.0/(l);

    viv_coord_t *udir = viv_coord_init( );
    viv_clone( udir, dir );   // udir = dir

    double multiplier = 0.0;
#ifdef A_REL_REL
    multiplier = grad * unit * weight;
    viv_multiply_by_x( udir, multiplier );
#else
    multiplier = grad * unit;
    viv_multiply_by_x(udir,multiplier);
#endif

    viv_plus( f, udir, f );
    tor_free( udir );
    tor_free( dir );
  }
  log_notice(LD_GENERAL,"Height vector force calculated as %0.2f. Will be multiplied by -1",f->_ht);
  f->_ht = -f->_ht;
  return f;
}

/** Apply the Vivaldi algorithm to our coordinate using the
 *  sample <b>s</b>.
 **/
static viv_coord_t *
viv_algorithm(viv_instance_t *node, viv_sample_t *s)
{
  //reject timeouts and self pings
  if (s->_latency <= 0)
    return 0;

  double weight  = viv_update_error(node, s);

  double t;
#ifdef A_REL_REL
  t = node->_timestep;
#else
  t = node->_pred_err;
  t = t / 2;
  if (t < 0 || t > 0.25) t = 0.25;
#endif
  log_notice(LD_GENERAL, "Using timestep of %.2f to compute new coordinate", t);

  // apply the force to our coordinates
  viv_coord_t *f = viv_net_force( node, s, weight );
  viv_multiply_by_x( f, t );
  viv_coord_t *new_coord = viv_coord_init( );
  viv_plus( node->_c, f, new_coord );
  tor_free( f );
  //  _c = _c + (f * t);

  /* MICAH: is this next "if" correct? */
  /* CHRIS: I don't think so. p2psim uses 1000. Are their units different? */
  /* CHRIS: Updated this to be '1'. p2psim notes that: '1000 = 1ms'. Since our
     coordinates are measuring in milliseconds, 1 millisecond should be 1
   */
  if(get_options()->VivPingUseHeight && node->_c->_ht <= 1)
    new_coord->_ht = 1;     //see lower down for an explanation

  assert(new_coord);
  return new_coord;
}

/** Apply the Vivaldi algorithm using the remote coordinate <b>c</b>,
 * the remote_error <b>e</b> and the empirically measured latency
 * <b>latency</b>.
 *
 * If we decide to update our coordinate, return 1, otherwise return zero.
 **/
char viv_update( viv_instance_t *node, viv_sample_t *sample)
{
  char res = 1;
  viv_coord_t *new_coord;
  char coord_str[512];

  viv_coord2string( node->_c, coord_str, sizeof(coord_str) );
  log_notice(LD_GENERAL, "Considering whether to update coordinate. Currently: %s",coord_str);

  if (!viv_prot_centroid_check(node,sample))
    res = 0;

  new_coord = viv_algorithm(node, sample);

  viv_coord2string( new_coord, coord_str, sizeof(coord_str) );
  log_notice(LD_GENERAL, "New candidate coord: %s",coord_str);

  if (!viv_prot_error_check(node,new_coord)){
    tor_free(new_coord);
    res = 0;
  }

  if (res)
  {
    viv_coord2string(new_coord, coord_str, sizeof(coord_str) );
    viv_prot_update_buffers(node, sample);
    update_stability(node,viv_dist(new_coord,node->_c));
    tor_free(node->_c);
    node->_c = new_coord;
    node->_nsamples += 1;
    log_notice( LD_GENERAL, "Updated coordinate. "
                            "New coordinate is %s. "
                            "[error: %0.4f stability: %0.4f",
                            coord_str,
                            node->_pred_err,node->stability);
  }
  else  {
    if (new_coord)
      tor_free(new_coord);
    log_notice(LD_GENERAL,"Did not update coordinate.");
  }
  return res;
}

static void
viv_prot_update_buffers(viv_instance_t *node, viv_sample_t *sample)
{
  const options_t *opt = get_options();

  //Update the error window
  smartlist_insert_sample( node->prot_err_window, 0, sample ); /* add at the beginning */
  while (smartlist_len(node->prot_err_window) > opt->VivProtectErrorWindow)
  {
    smartlist_pop_last_sample(node->prot_err_window);
  }
  //Update the centroid window
  smartlist_insert_sample( node->prot_centroid_window, 0, sample ); /* add at the beginning */
  while (smartlist_len(node->prot_centroid_window) > opt->VivProtectCentroidWindow)
  {
    smartlist_pop_last_sample(node->prot_centroid_window);
  }
}

viv_instance_t *
viv_instance_initialize()
{

  viv_instance_t *node = (viv_instance_t *)tor_malloc( sizeof(viv_instance_t) );
  node->_nsamples = 0;
  node->_dim = VIV_DIMENSIONS;

  node->_timestep = get_options()->VivTimestep;
  node->_pred_err  = 1;

  node->_c = viv_coord_init( );

  node->_memory = smartlist_new();
  node->prot_centroid_window = smartlist_new();
  node->prot_err_window = smartlist_new();
  node->stability_data= smartlist_new();

  node->stability = -1;

  log_info( LD_GENERAL, "Vivaldi initialized with %u dimensions" , node->_dim);

  return node;
}

int32_t
viv_instance_initialize_existing(viv_instance_t *node)
{
  if (!node)
    return -1;

  node->_nsamples = 0;
  node->_dim = VIV_DIMENSIONS;

  node->_timestep = get_options()->VivTimestep;
  node->_pred_err  = 1;

  node->_c = viv_coord_init( );

  node->_memory = smartlist_new();
  node->prot_centroid_window = smartlist_new();
  node->prot_err_window = smartlist_new();
  node->stability_data= smartlist_new();

  node->stability = -1;

  log_info( LD_GENERAL, "Vivaldi initialized with %u dimensions" , node->_dim);
  return 0;
}


#define VIV_DIM_TYPE_FLOAT (1 << 0)
#define VIV_DIM_TYPE_DOUBLE (1 << 1)

/** Serialize the coordinate <b>coord</b> and its predicted error <b>est_error</b>
 * into the buffer <b>buf</b> of size <b>sz</b>.
 *
 * Returns the number of bytes of data written to <b>buf</b>, or zero if <b>buf</b>
 * is not large enough or the <b>coord</b> is null.
 **/
uint16_t
viv_serialize_coord( const viv_coord_t *coord, double est_error, char *buf, uint32_t sz )
{
  if (coord == NULL)
  {
    log_notice(LD_GENERAL,"viv_serialize_coord: coord was null. Couldn't serialize");
    return 0;
  }

  uint32_t bytes_required = VIV_SERIALIZED_COORD_SIZE;
  if (sz < bytes_required)
  {
    log_notice(LD_GENERAL, "viv_serialize_coord: Not enough size in buffer to serialize. Required: %u; Available %u, coord->_dimensions are: %u",
        bytes_required, sz,coord->_dimensions);
    return 0;
  }

  uint8_t *ptr = (uint8_t *)buf;
  uint32_t offset = 0;

  memcpy_type(uint8_t, VIV_DIMENSIONS, buf, offset);

#ifdef VIV_SERIALIZE_AS_FLOATS
  memcpy_type(uint8_t,VIV_DIM_TYPE_FLOAT, buf, offset);
#else
  memcpy_type(uint8_t,VIV_DIM_TYPE_DOUBLE, buf, offset);
#endif

  uint8_t c;
  for (c = 0; c < VIV_DIMENSIONS; c++)
  {
#ifdef VIV_SERIALIZE_AS_FLOATS
    memcpy_type(float,coord->_v[c],ptr,offset);
#else
    memcpy_type(double,coord->_v[c],ptr,offset);
#endif
  }

#ifdef VIV_SERIALIZE_AS_FLOATS
  memcpy_type(float,coord->_ht,ptr,offset);
  memcpy_type(float,est_error,ptr,offset);
#else
  memcpy_type(double,coord->_ht,ptr,offset);
  memcpy_type(double,est_error,ptr,offset);
#endif

  tor_assert(offset == bytes_required);
  return offset;
}


/** Deserialize a coordinate encoded in <b>buf</b> and return it. Also populate
 * the value of <b>remote_error</b> with the remote error serialized in <b>buf</b>.
 */
viv_coord_t *
viv_deserialize_coord( char *buf,double *remote_error )
{
  if (buf == NULL)
    return NULL;

  uint32_t offset = 0;
  viv_coord_t *coord;
  uint8_t dim;
  memcpy( &dim, buf + offset, sizeof(uint8_t) );
  offset += sizeof(uint8_t);

  // sanity check
  if (dim != VIV_DIMENSIONS)
  {
    log_warn( LD_GENERAL, "Received Vivaldi message with unsupported number of dimensions: %d", dim );
    return NULL;
  }

  uint8_t dim_type;
  memcpy(&dim_type,buf+offset,sizeof(uint8_t));
  offset += sizeof(uint8_t);

  coord = viv_coord_init( );
  uint8_t c;
  float tmp;
  for (c = 0; c < coord->_dimensions; c++)
  {
    switch (dim_type) {
      case VIV_DIM_TYPE_FLOAT:
        memcpy(&tmp,buf+offset,sizeof(float));
        coord->_v[c] = tmp;
        offset += sizeof(float);
        break;
      case VIV_DIM_TYPE_DOUBLE:
        memcpy( &coord->_v[c], buf + offset, sizeof(double) );
        offset += sizeof(double);
        break;
      default:
        tor_assert(0);
    }
  }

  switch (dim_type) {
    case VIV_DIM_TYPE_FLOAT:
      memcpy( &tmp, buf + offset, sizeof(float) );
      offset += sizeof(float);
      coord->_ht = tmp;
      memcpy( &tmp, buf + offset, sizeof(float) );
      offset += sizeof(float);
      *remote_error = tmp;
      break;
    case VIV_DIM_TYPE_DOUBLE:
      memcpy( &coord->_ht, buf + offset, sizeof(double) );
      offset += sizeof(double);
      memcpy( remote_error, buf + offset, sizeof(double) );
      offset += sizeof(double);
      break;
    default:
      tor_assert(0);
  }

  return coord;
}

/** Write a null-terminated, human readable string representation of <b>coord</b> to <b>buf</b>.
 * If the length of the coordinate is longer than the length of <b>buf</b> as given by
 * <b>bufsize</b>, the coordinate will be truncated.
 **/
void
viv_coord2string( const viv_coord_t *coord, char *buf, uint16_t bufsize )
{
  uint16_t remaining = bufsize;
  char coord_str[4096];

  if (coord == NULL)
  {
    snprintf( buf, remaining - 1, "[ empty ]" );
    return;
  }

  strcpy( buf, "[ " );
  remaining = bufsize - 3;  /* includes space for \0 */
  uint8_t c;
  for (c = 0; c < coord->_dimensions; c++)
  {
    //remaining -= snprintf( buf, remaining, "%s %.2f", buf, coord->_v[c] );
    snprintf(coord_str, sizeof(coord_str), "%.2f ", coord->_v[c]);
    remaining -= strlen(coord_str);
    strncat(buf, coord_str, remaining);
    if (remaining <= 0)
      return;
  }
  //snprintf( buf, remaining, "%s ]", buf );
  if (get_options()->VivPingUseHeight)
  {
    snprintf(coord_str, sizeof(coord_str), "] ht=%.2f", coord->_ht);
    remaining -= strlen(coord_str);
    strncat(buf, coord_str, remaining);
  } else {
    strncat(buf, "]", remaining);
  }
}

/** Record a new viv_sample_t in <b>node</b>, containing the
 * remote coordinate <b>coord</b>, remote estimated error <b>e</b> and
 * measured latency <b>latency</b>. The remote node has the identity
 * digest <b>remote_id_digest</b>.
 *
 * Always saves the new sample at </b>node</b>->memory[0].
 **/
viv_sample_t *
viv_record_ping_sample( viv_instance_t *node, viv_coord_t *coord, double latency, double e, const char* remote_id_digest )
{
  char buf[4096];
  viv_coord2string( coord, buf, 4096 );
  buf[4095] = '\0';
  const options_t *options = get_options();
  uint32_t vivaldi_memory_size = (options->VivMemorySize > options->VivUnprotectedBootstrapCount) ?
                                      options->VivMemorySize : options->VivUnprotectedBootstrapCount;
  tor_assert( vivaldi_memory_size > 0 );

  log_notice( LD_GENERAL,
      "Recording sample for %s (latency=%.2f) (error=%.2f) (coord=%s)",
      remote_id_digest,
      latency,
      e,
      buf );

  /* first, add our sample */
  viv_sample_t *sample = viv_sample_init( coord, latency, e );
  smartlist_insert_sample( node->_memory, 0, sample ); /* add at the beginning */
  while ((uint32_t)smartlist_len(node->_memory) > vivaldi_memory_size) {
    smartlist_pop_last_sample(node->_memory);
  }
  return sample;
}

/** Returns 1 if the new sample moves our centroid
 *  of neighbors towards the origin, or if we pull
 *  a random number > VivProtectCentroidRejectRate
 *  out of a hat.
 *  0 otherwise.
 **/
static char
viv_prot_centroid_check(viv_instance_t *node, viv_sample_t *s)
{
  log_notice(LD_GENERAL,"[CentroidProtect] Checking with history of %u",
                        smartlist_len(node->prot_centroid_window));
  int history_size = smartlist_len(node->_memory);
  /* if we're just starting out, then always update */
  if (history_size < get_options()->VivUnprotectedBootstrapCount) {
    log_notice(LD_GENERAL,"[CentroidProtect] Disabled (bootstrapping %u/%u).",history_size,get_options()->VivUnprotectedBootstrapCount);
    return 1;
  }

  viv_coord_t *neighbor_centroid = viv_coord_init();
  viv_coord_t *new_centroid = viv_coord_init();
  viv_coord_t *origin = viv_coord_init();
  double old_origin_dist = 0.0, new_origin_dist = 0.0;

  SMARTLIST_FOREACH(node->prot_centroid_window, viv_sample_t*, hist_s,
  {
    viv_plus(neighbor_centroid,hist_s->_c,neighbor_centroid);
    viv_plus(new_centroid,hist_s->_c,new_centroid);
  });
  viv_divide(neighbor_centroid,smartlist_len(node->prot_centroid_window));
  viv_plus(new_centroid,s->_c,new_centroid);
  viv_divide(new_centroid,1 + smartlist_len(node->prot_centroid_window));

  old_origin_dist = viv_dist(origin,neighbor_centroid);
  new_origin_dist = viv_dist(origin,new_centroid);

  #define cent_fmt "(old: %0.2f new: %0.2f)"
  #define cent_fmt_args old_origin_dist, new_origin_dist

  if (new_origin_dist > old_origin_dist) {
    double k = ((double)crypto_rand_uint64(1000)) / 1000.0;
    if (k < get_options()->VivProtectCentroidRejectRate) {
      log_notice(LD_GENERAL,"[CentroidProtect] Failed. Rejected. "
                            cent_fmt
                            " [CentroidRejectRate: %.2f, k: %.2f]",
                            cent_fmt_args,
                            get_options()->VivProtectCentroidRejectRate,
                            k);
      return 0;

    } else {

      log_notice(LD_GENERAL,"[CentroidProtect] Failed. Accepted. "
                            cent_fmt
                            " [CentroidRejectRate: %.2f, k: %.2f]",
                            cent_fmt_args,
                            get_options()->VivProtectCentroidRejectRate,
                            k);
    }
  } else {
    log_notice(LD_GENERAL,"[CentroidProtect] Passed. Accepted. "cent_fmt,cent_fmt_args);
  }
  tor_free(new_centroid);
  tor_free(origin);
  tor_free(neighbor_centroid);
  return 1;
  #undef cent_fmt
  #undef cent_fmt_args
}

/* Returns 1 iff we believe that we're better off
 * upgrading to a new coordinate <b>new_coord</b>.
 */
static char
viv_prot_error_check( viv_instance_t *node, viv_coord_t *new_coord )
{
  tor_assert( node );
  tor_assert( new_coord );

  log_notice(LD_GENERAL,"[ErrorProtect] Checking with a history of %u",
              smartlist_len(node->prot_err_window));
  int history_size = smartlist_len(node->_memory);
  /* if we're just starting out, then always update */
  if (history_size < get_options()->VivUnprotectedBootstrapCount) {
    log_notice(LD_GENERAL,"[ErrorProtect] Disabled (bootstrapping).");
    return 1;
  }

  double *errors = (double *)tor_malloc( history_size * sizeof(double) );

  /* compute estimation error using past histories and our current coord */
  SMARTLIST_FOREACH( node->prot_err_window, viv_sample_t *, s, {
      double vdist = viv_dist(node->_c, s->_c);
      double adist = s->_latency;
      /* XXX This might not be right:
       * We want to adjust the errors so that if the remote
       * node has a very high error relative to ours, we don't
       * count the relative error so high. If we did, then we'd constantly
       * be throwing out coordinate adjustments because they don't meet the
       * standards when compared to coordinates that are probably wrong anyway.
       */
      double weight = 1.0 - (node->_pred_err > s->_error) ? node->_pred_err : s->_error;
      errors[s_sl_idx] = fabs(vdist - adist) * weight;
      });
  double error_now = median_double(errors, smartlist_len(node->prot_err_window));

  /* recompute estimation error using past histories and our candidate new coord */
  SMARTLIST_FOREACH( node->prot_err_window, viv_sample_t *, s, {
      double vdist = viv_dist(new_coord, s->_c);
      double adist = s->_latency;
      /* XXX This might not be right:
       * We want to adjust the errors so that if the remote
       * node has a very high error relative to ours, we don't
       * count the relative error so high. If we did, then we'd constantly
       * be throwing out coordinate adjustments because they don't meet the
       * standards when compared to coordinates that are probably wrong anyway.
       */
      double weight = 1.0 - (node->_pred_err > s->_error) ? node->_pred_err : s->_error;
      errors[s_sl_idx] = fabs(vdist - adist) * weight;
      });
  double error_future = median_double(errors,smartlist_len(node->prot_err_window));

  tor_free( errors );

  #define err_fmt "(old: %0.2f new: %0.2f)"
  #define err_fmt_args error_now, error_future
  if (error_future > error_now) {
    // Time to decide if we're going to accept this even though it failed.
    double k = ((double)crypto_rand_uint64(1000)) / 1000.0;
    if (k < get_options()->VivProtectErrorRejectRate) {
      //We reject
      log_notice( LD_GENERAL, "[ErrorProtect] Failed. Rejected. "
                              err_fmt
                              "[ErrRejectRate: %.2f, k: %.2f]",
                              err_fmt_args,
                              get_options()->VivProtectErrorRejectRate,
                              k);

      return 0;
    } else {
      log_notice( LD_GENERAL, "[ErrorProtect] Failed. Accepted. "
                              err_fmt
                              "[ErrRejectRate: %.2f, k: %.2f]",
                              err_fmt_args,
                              get_options()->VivProtectErrorRejectRate,
                              k);
    }
  } else {
    log_notice( LD_GENERAL, "[ErrorProtect] Passed. Accepted. "
                            err_fmt,
                            err_fmt_args);
  }

  return 1;
  #undef err_fmt
  #undef err_fmt_args
}

viv_instance_t *
get_or_create_viv_instance()
{
  viv_instance_t * my_viv = 0;
  if (!my_vivaldi) {
    log_notice(LD_OR,"Lost my_vivaldi instance... Reinitializing, but have lost all history");
    my_viv = viv_instance_initialize();
    my_vivaldi = my_viv;
  } else {
    my_viv = my_vivaldi;
  }

  return my_viv;
}

/** Hex encode the coordinate <b>coord</b> along with the predicted
 *  error value <b>confidence</b> into <b>buffer</b>.
 **/
void
viv_hex_encode_coord(const viv_coord_t *coord, double confidence, char *buffer, size_t sz)
{
  char serialized_coord[512];
  uint16_t bytes;
#ifdef VIVALDI_MALICIOUS
  const or_options_t *options = get_options();
  double VivMaliciousCoordinateMax = options->VivMaliciousCoordinateMax;
  int i;

  if (options->VivMaliciousLieToDirectories && VivMaliciousCoordinateMax != 0) {
    viv_coord_t fake_coords;
    for (i = 0; i < VIV_DIMENSIONS; i++)
      fake_coords._v[i] = (crypto_rand_double() * VivMaliciousCoordinateMax) - (VivMaliciousCoordinateMax);
    fake_coords._dimensions = VIV_DIMENSIONS;

    bytes = viv_serialize_coord( &fake_coords, 0.0,  serialized_coord, sizeof(serialized_coord));
    tor_assert(bytes == VIV_SERIALIZED_COORD_SIZE);
  } else
#endif
  {
    bytes = viv_serialize_coord( coord, confidence,  serialized_coord, sizeof(serialized_coord));
    tor_assert(bytes == VIV_SERIALIZED_COORD_SIZE);
  }

  base16_encode(buffer, sz, serialized_coord, bytes);
  /*printf( "serialized coord in hex: %s (length=%d)\n", buffer, (bytes*2)+1);*/
}

/** Decode a hex encoded coordinate from <b>buffer</b> and
 * store it (and the associated remote error in <b>dst</b>.
 * Return -1 if unsuccessful, 0 otherwise.
 **/
char
viv_hex_decode_coord(viv_coord_t *dst, double * confidence, char *buffer, int sz)
{
    char serialized[VIV_SERIALIZED_COORD_SIZE*2];

    if (sz < (int)(VIV_SERIALIZED_COORD_SIZE * 2))
        return -3;

    if (base16_decode((char *)serialized, sizeof(serialized),buffer,VIV_SERIALIZED_COORD_SIZE*2) < 0)
        return -1;

    viv_coord_t *tmp;

    tmp = viv_deserialize_coord(serialized,confidence);

    if (!tmp || !dst)
        return -2;

    //We need to copy the data over, because we only have a single pointer. If we set it, we lose
    //it where we called the function.
    memcpy(dst,tmp,sizeof(viv_coord_t));

    /*char coord[500];*/
    /*viv_coord2string(tmp,coord,500);*/
    /*printf("Decoded coordinate to %s\n",coord);*/

    return 0;
}

#define MARK_DESCRIPTOR_INTERVAL 60

static int
_double_compare_descending(const void *a, const  void *b)
{
    double * da = (double *) a;
    double * db = (double *) b;

    if (*da == *db)    return 0;
    if (*da < *db) return 1;    return -1;
}

static inline int
sl_double_compare(const void **a, const void **b)
{
    return _double_compare_descending(*a,*b);
}

static inline int
safe_isnan(double *d)
{
  return (*(volatile double *)d) != *d;
}

static inline int
viv_coord_is_valid(viv_coord_t *coord)
{
  if (!coord)
    return 0;

  int i;
  for (i = 0; i < VIV_DIMENSIONS; i++)
    if (safe_isnan(&(coord->_v[i])))
      return 0;

  return 1;
}

/** Check whether or not the distance reported in the coordinate is greater
 * than VivMaxCoordDist. If it is, then scale the coordinate down until it
 * is only VivMaxCoordDist away.
 **/
static inline void
viv_coord_scale(viv_coord_t *self_coord, viv_coord_t *reported_coord)
{
  char buf1[256], buf2[256];
  double max_dist = get_options()->VivMaxCoordDist;

  if (max_dist <= 0.0)
    return;

  double actual_dist = viv_dist(self_coord,reported_coord);
  double multiplier = max_dist / actual_dist;

  if (multiplier > 1)
    return; //Scaling is unnecessary

  viv_coord2string(reported_coord,buf1,256);

  // Copy the received coord
  viv_coord_t *tmp_coord = viv_coord_init();
  viv_clone(tmp_coord,reported_coord);
  //Shift the copied coord by the offset
  viv_minus(tmp_coord,self_coord,tmp_coord);

  //Multiply by our multiplier
  viv_multiply_by_x(tmp_coord,multiplier);
  //Add back in the offset to put us in the right place
  viv_plus(self_coord,tmp_coord,reported_coord);
  viv_coord2string(reported_coord,buf2,256);
  actual_dist = viv_dist(self_coord,reported_coord);
  log_notice(LD_GENERAL,"Adjusted reported coordinate from %s to %s. Distance reduced to %0.2f",
              buf1,buf2,actual_dist);
}


struct coord_stability
{
  time_t recorded;
  double change;
};

#define MAX_STABILITY_MEASURES 30

/** Update the stability of this nodes coordinates */
static void
update_stability(viv_instance_t *node,double change)
{
  struct coord_stability *cs = (struct coord_stability*)tor_malloc(sizeof(struct coord_stability));
  cs->recorded = approx_time();
  cs->change = change;

  smartlist_insert(node->stability_data,0,cs);
  while (smartlist_len(node->stability_data) > MAX_STABILITY_MEASURES) {
    struct coord_stability * old = (struct coord_stability*)smartlist_pop_last(node->stability_data);
    tor_free(old);
  }

  time_t oldest = 0;
  double sum_change = 0.0;

  SMARTLIST_FOREACH(node->stability_data,struct coord_stability *,stab,
  {
    if (stab_sl_idx == smartlist_len(node->stability_data)-1)
      oldest = stab->recorded;

    sum_change += stab->change;
  });

  log_notice(LD_GENERAL,"Recalculating stability from %u elements. [sum_delta: %0.2f, time: %lu]",smartlist_len(node->stability_data),sum_change, cs->recorded - oldest );

  node->stability = sum_change / ((double)(cs->recorded - oldest));
}

#ifdef USE_VIVALDI_IMPERATIVE_SELECTION
/** Returns the f_s(,x) from Snader and Borisov's Tunable Tor
 * for a given s value.
 */
double
snader_borisov_selection_function(double s)
{
    double x = ((double) crypto_rand_uint64(INT_MAX)) / (double) INT_MAX;
    double fn = x;

    if (s > 0) {
        fn = (1.0 - pow(2.0, s * x)) / (1.0 - pow(2.0, s));
    }

    log_info(LD_OR, "snader_borisov_selection_function: s=%f x=%f fn=%f", s, x, fn);

    return fn;
}
#endif

/** Copy coordinate information from one structure to another. **/
void
viv_copy_coord_info(viv_coord_info_t *dst, viv_coord_info_t *src)
{
  viv_clone(&(dst->coord),&(src->coord));
  dst->error = src->error;
}

#ifdef __cplusplus
}
#endif

