//struct sql_conn {
#include <semaphore.h>
#include "queue_calc.h"
#include "main.h"

#ifndef SQL_THR
#define SQL_THR
struct sdata_MySQL{
 char *host;
 char *user;
 char *pass;
 char *db;
 char *table;
#ifdef  LINT_CFG
 long int  diff;
#else
 int  diff;
#endif
 sem_t *psem_sql;
 Q_cl<unit_data> *pq;
 Q_cl<unit_data> *pq_thr;
};

void * f_thr_sql(void *arg);

#endif
