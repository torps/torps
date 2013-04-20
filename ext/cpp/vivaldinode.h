#ifndef __VIVALDINODE_H__
#define __VIVALDINODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "container.h"
#include "cpp_interface.hh"
#include "assert.h"

#define MODEL_EUCLIDEAN 3
#define ALG_VIVALDI 1
#define A_REL_REL

/** To save space, we can serialize coordinates as floats without really
 *  losing much precision
 **/
#undef VIV_SERIALIZE_AS_FLOATS
#ifdef VIV_SERIALIZE_AS_FLOATS
#define VIV_SERIALIZED_COORD_SIZE (sizeof(uint8_t) + sizeof(uint8_t) + \
                                  (VIV_DIMENSIONS * sizeof(float))  + \
                                  sizeof(float) + sizeof(float))
#else
#define VIV_SERIALIZED_COORD_SIZE (sizeof(uint8_t) + sizeof(uint8_t) + \
                                  (VIV_DIMENSIONS * sizeof(double)) + \
                                  sizeof(double) + sizeof(double))
#endif

/** The number of dimensions in a Vivaldi coordinate*/
#define VIV_DIMENSIONS 3

/** A single Vivaldi coordinate. **/
typedef struct VIV_COORDINATE {
    uint8_t _dimensions; /**< The number of dimensions **/
    /** An array of <b>_dimensions</b> doubles, each of which
     * represents a directioncal vector in the coordinate **/
    double _v[VIV_DIMENSIONS];
    double _ht;
} viv_coord_t;

typedef struct viv_coord_info_t {
  viv_coord_t coord;
  double error;
} viv_coord_info_t;


/** The parent data structure for almost all Vivaldi related
 * data. **/
typedef struct VIV_NODE
{
    uint32_t _nsamples; /**< how many times sample() has been called **/
    uint8_t _dim; /**< dimensionality of the fit space **/
    double _timestep; /**< minimum timestep **/
    double _pred_err; /**< running average of prediction error **/

    viv_coord_t *_c; /**< Current estimated coordinates **/

    /** array of this node's previous Vivaldi samples
     * (of length vivaldi_memory_size) **/
    smartlist_t *_memory;
    /** the samples to use to check centroid protection **/
    smartlist_t *prot_centroid_window;
    /** the samples to use to check centroid protection **/
    smartlist_t *prot_err_window;

    //Stability measurement stuff
    smartlist_t * stability_data;

    /** The rate of coordinate change. **/
    double stability;
    /**The difference between expected and actual latencies. **/
    double relative_error;

    options_t options;

    /*  These are specific to the CoordinateEngine */
    char nodeid[64];
    uint32_t congestion_ident;

} viv_instance_t;

typedef struct VIV_SAMPLE viv_sample_t;

double viv_dist(const viv_coord_t *a, const viv_coord_t *b);
char viv_sample( viv_instance_t *node,
                 viv_coord_t *c,
                 double e,
                 double latency);
void viv_clone( viv_coord_t *dest, viv_coord_t *source );
uint16_t viv_serialize_coord( const viv_coord_t *coord,
                              double est_error,
                              char *buf,
                              uint32_t sz );
viv_coord_t *viv_deserialize_coord( char *buf, double *remote_error );
void viv_coord2string(const viv_coord_t *coord, char *buf, uint16_t bufsize );
void viv_hex_encode_coord(const viv_coord_t *coord,
                          double confidence,
                          char *buffer,
                          size_t sz);
char viv_hex_decode_coord(viv_coord_t *dst,
                          double *confidence,
                          char *buffer,
                          int sz);

void viv_copy_coord_info(viv_coord_info_t *dst, viv_coord_info_t *src);

#ifdef USE_VIVALDI_IMPERATIVE_SELECTION
double
snader_borisov_selection_function(double s);
#endif

viv_instance_t * viv_instance_initialize();
int32_t viv_instance_initialize_existing(viv_instance_t *node);
void viv_node_free( viv_instance_t *node );
viv_instance_t * get_or_create_viv_instance();

/** Creates a new Vivaldi coordinate **/
viv_coord_t * viv_coord_init( );
void viv_coord_free( viv_coord_t *coord );
uint32_t viv_coord_equal(const viv_coord_t *c1, const viv_coord_t *c2);
const viv_coord_t *viv_info_get_coord(const viv_coord_info_t *ci);

viv_sample_t *
viv_record_ping_sample( viv_instance_t *node, viv_coord_t *coord,
                        double latency, double e, const char * );

double snader_borisov_selection_function(double s);
char viv_update( viv_instance_t *node, viv_sample_t *sample);

#ifdef __cplusplus
}
#endif
#endif

