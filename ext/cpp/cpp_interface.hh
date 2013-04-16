#ifndef CPP_INTERFACE_H_AI8TVQFC
#define CPP_INTERFACE_H_AI8TVQFC
#ifdef __cplusplus
extern "C" { 
#endif

typedef struct options {

  int VivPingUseHeight;
  int VivProtectErrorWindow;
  int VivProtectCentroidWindow;
  int VivMemorySize;
  int VivUnprotectedBootstrapCount;
  double VivMaxCoordDist;

  double VivTimestep;
  double  VivProtectCentroidRejectRate;
  double  VivProtectErrorRejectRate;

} options_t;

const options_t *get_options();
  
#ifdef __cplusplus
}
#endif


#endif /* end of include guard: CPP_INTERFACE_H_AI8TVQFC */


