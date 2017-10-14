#include <semaphore.h>

#include "queue_calc.h"
//#include "main.h"

#ifndef DATA_SOC
#define DATA_SOC

struct sdata_Socket{
 char *host;
#ifdef LINT_CFG
 long int  port;
#else
 int  port;
#endif
 sem_t *psem_sql;
 Q_cl<unit_data> *pq;
 Q_cl<unit_data> *pq_thr;
};

#endif
void * f_thr_scl(void *arg);

