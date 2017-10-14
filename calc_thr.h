#include <semaphore.h>
#include <openssl/ec.h> // for EC_KEY definition
#include "queue_calc.h"
#include "calc_data.h"

#ifdef OCL_CLIENT
#include "cl_cl.h"
#endif

//#define CountR  65536
//#define CountC  10

//static  EC_POINT *MPoint[CountC*CountR];

extern EC_POINT *MPoint[CountR_CL*CountC_CL];
extern  EC_KEY* pkey;
extern  const EC_GROUP *group;
extern  BN_CTX *ctx;


struct calc_thr_param
{
  long long int id_thr;
  int   i_typecalc;
  int   i_countcalc;
  sem_t *psem_sql;
  sem_t *psem_calc;
  Q_cl<unit_data>  *pq;
  Q_cl<unit_data>  *pq_thr;

#ifdef OCL_CLIENT
  CCl_  *pcl;
#endif
};

void *f_thr_calc(void *arg);
void *f_thr_calc_cl(void *arg);
void *f_thr_calc_cache(void *arg);
void init_table();