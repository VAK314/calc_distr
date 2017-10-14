#include <curses.h>
#include <stdio.h>
//#include <string>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <openssl/ecdsa.h>
#include <openssl/ec.h> // for EC_KEY definition
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "main.h"
#include "calc_thr.h"


#define  count_data 10
#define  index_data 300000000
//#define  index_data 300
#define  end_data   4000000000
#define  max_xorlen 45


int calc_t(unit_data temp_data,calc_thr_param* param,FILE* fileout){


int iTable[] = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3,
        4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4,
        4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2,
        3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5,
        4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4,
        5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3,
        3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2,
        3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
        4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
        3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6,
        4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
    };


  int ii,iii;
  char *pEnd;
  char str_byte[3];
  unsigned char vchSecret_z[32];
  unsigned char vchSecret_cpy[32];
  unsigned char vchTop10Secret_z[count_data][20];
  unsigned char uc_min[count_data];
  int count_xor;
  bool second_round = false;

  unsigned char u_byte;
  unsigned long long count_calc=0;
  unsigned long long count_step=0;
  unsigned long long old_count_step=0;

  EC_POINT *pub_key_t1 = NULL;
  EC_POINT *pub_key_t2 = NULL;

  const EC_POINT *pgen;

    count_step=strtol(temp_data.str_nb,&pEnd,10);
    old_count_step=count_step;

    memset(&vchSecret_z[0], 0, 32);
    if(strlen(temp_data.str_hb)<40)
    {
      printw("Size of beginstr=40 but %lu\n",strlen(temp_data.str_hb));
      return 0;
    }
    fprintf(fileout,"%lli\x09%s\x09 0\n",count_step,temp_data.str_hb);
    for(ii=0;ii<20;ii++)
    {
      strncpy(str_byte,temp_data.str_hb+ii*2,2);
      u_byte=strtol(str_byte,&pEnd,16);
      memset(&vchSecret_z[ii+12],u_byte, 1);
    }
    memcpy(vchSecret_cpy,vchSecret_z,32);
    count_calc=temp_data.diff;
    printw("count zero=%lli\n", count_calc);

  pub_key_t1 = EC_POINT_new(group);
  pub_key_t2 = EC_POINT_new(group);

  unsigned char hash1[SHA256_DIGEST_LENGTH];

  time_t t_start = time(NULL);
  time_t t_end ;

  long long tt1;
  std::vector<unsigned char> vchPubKey(33, 0);
  unsigned char* pbegin = &vchPubKey[0];



  do
  {


  EC_POINT_add(group, pub_key_t1,MPoint[7*CountR_CL+((*((unsigned int*)(&vchSecret_z[12])))&0xfffff)], MPoint[6*CountR_CL+(((*((unsigned int*)(&vchSecret_z[14])))>>4)&0xfffff)],ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[5*CountR_CL+((*((unsigned int*)(&vchSecret_z[17])))&0xfffff)],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[4*CountR_CL+(((*((unsigned int*)(&vchSecret_z[19])))>>4)&0xfffff)],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[3*CountR_CL+((*((unsigned int*)(&vchSecret_z[22])))&0xfffff)],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[2*CountR_CL+(((*((unsigned int*)(&vchSecret_z[24])))>>4)&0xfffff)],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[CountR_CL+((*((unsigned int*)(&vchSecret_z[27])))&0xfffff)],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[(((*((unsigned int*)(&vchSecret_z[29])))>>4)&0xfffff)],pub_key_t2,ctx);
/*
    EC_POINT_add(group, pub_key_t1,MPoint[CountR+*(unsigned short*)(&vchSecret_z[28])], MPoint[*(unsigned short*)(&vchSecret_z[30])],ctx);
    EC_POINT_add(group, pub_key_t2,MPoint[2*CountR+*(unsigned short*)(&vchSecret_z[26])],pub_key_t1,ctx);
    EC_POINT_add(group, pub_key_t1,MPoint[3*CountR+*(unsigned short*)(&vchSecret_z[24])],pub_key_t2,ctx);
    EC_POINT_add(group, pub_key_t2,MPoint[4*CountR+*(unsigned short*)(&vchSecret_z[22])],pub_key_t1,ctx);
    EC_POINT_add(group, pub_key_t1,MPoint[5*CountR+*(unsigned short*)(&vchSecret_z[20])],pub_key_t2,ctx);
    EC_POINT_add(group, pub_key_t2,MPoint[6*CountR+*(unsigned short*)(&vchSecret_z[18])],pub_key_t1,ctx);
    EC_POINT_add(group, pub_key_t1,MPoint[7*CountR+*(unsigned short*)(&vchSecret_z[16])],pub_key_t2,ctx);
    EC_POINT_add(group, pub_key_t2,MPoint[8*CountR+*(unsigned short*)(&vchSecret_z[14])],pub_key_t1,ctx);
    EC_POINT_add(group, pub_key_t1,MPoint[9*CountR+*(unsigned short*)(&vchSecret_z[12])],pub_key_t2,ctx);
*/
    EC_POINT_point2oct(group, pub_key_t1,POINT_CONVERSION_COMPRESSED,pbegin,33,ctx);
    SHA256(&vchPubKey[0], vchPubKey.size(), hash1);
    RIPEMD160(hash1, sizeof(hash1), &vchSecret_z[12]);

    if(count_step>=index_data)
    {
	if(second_round) break;
	if(count_step<index_data+count_data) 
	{   temp_data.bCommand=SEND_WT; 
	    fprintf(fileout,"%lli\x09",count_step);
	    sprintf(temp_data.str_nb,"%lli",count_step);
            temp_data.str_hb[0]=0;
	    memcpy(&vchTop10Secret_z[count_step-index_data][0], &vchSecret_z[12],20);
	    for(ii=0;ii<20;ii++)
	    {
    		fprintf(fileout,"%02x",vchSecret_z[12+ii]);
    		sprintf(str_byte,"%02x",vchSecret_z[12+ii]);
    		strcat(temp_data.str_hb,str_byte);
    	    }
    	    fprintf(fileout,"\x09testdata N=%lli\n",count_step-index_data);
    	    param->pq->WriteQ(&temp_data);
    	    sem_post(param->psem_sql);
	}
    }
    if((count_step>=index_data+count_data)||(second_round))
    {
	//check xorlen
            for(iii=0;iii<count_data;iii++)
    	    {
		count_xor = 0;
        	for(ii=0;ii<20;ii++)
		{
		    count_xor +=iTable[vchSecret_z[ii+12]^vchTop10Secret_z[iii][ii]];
		}
		if(count_xor<=max_xorlen)
      		{	
		    fprintf(fileout,"%lli\x09",count_step);
		    temp_data.bCommand=SEND_WT; 
		    sprintf(temp_data.str_nb,"%lli",count_step);
		    temp_data.str_hb[0]=0;
		    for(ii=0;ii<20;ii++)
    		    {
    			fprintf(fileout,"%02x",vchSecret_z[12+ii]);
    			sprintf(str_byte,"%02x",vchSecret_z[12+ii]);
    			strcat(temp_data.str_hb,str_byte);
    		    }
	    	    fprintf(fileout,"\x09n=%d\x09xor=%d\n",iii,count_xor);
    		    param->pq->WriteQ(&temp_data);
    		    sem_post(param->psem_sql);
		}
    	    }
	    
    }

    if((memcmp(vchSecret_z,&vchSecret_z[12],count_calc)==0)&&(second_round==false))
    {
      fprintf(fileout,"%lli\x09",count_step);

      temp_data.bCommand=SEND_W; 
      sprintf(temp_data.str_nb,"%lli",count_step);
      temp_data.str_hb[0]=0;
      for(ii=0;ii<20;ii++)
      {
        fprintf(fileout,"%02x",vchSecret_z[12+ii]);
        sprintf(str_byte,"%02x",vchSecret_z[12+ii]);
        strcat(temp_data.str_hb,str_byte);
      }
      param->pq->WriteQ(&temp_data);
      sem_post(param->psem_sql);
      t_end = time(NULL);
      fprintf(fileout,"\x09%ld",t_end-t_start);
      if(t_end-t_start!=0) fprintf(fileout,"\x09%d",(int)((count_step-old_count_step)/(t_end-t_start)));
      old_count_step=count_step;
      fprintf(fileout,"\n");
      t_start=t_end;
    }
    count_step++;
    if(count_step>end_data)
    {
	count_step=0;
	second_round = true;
        memcpy(vchSecret_z,vchSecret_cpy,32);
    }
  }
  while(count_calc>0);
};



int calc_main(unit_data temp_data,calc_thr_param* param,FILE* fileout){

  int ii;
  char *pEnd;
  char str_byte[3];
  unsigned char vchSecret_z[32];
//  string str_sb=""; 
  unsigned char u_byte;
  unsigned long long count_calc=0;
  unsigned long long count_step=0;
  unsigned long long old_count_step=0;

//t  EC_KEY* pkey;
//t  EC_POINT *pub_key = NULL;
  EC_POINT *pub_key_t1 = NULL;
  EC_POINT *pub_key_t2 = NULL;



//t  BIGNUM *priv_key;
  const EC_POINT *pgen;
//t  const EC_GROUP *group;
//t  BN_CTX *ctx = NULL;

    count_step=strtol(temp_data.str_nb,&pEnd,10);
    old_count_step=count_step;
//    str_sb = (const char*) temp_data.str_hb;

    memset(&vchSecret_z[0], 0, 32);
    if(strlen(temp_data.str_hb)<40)
    {
      printw("Size of beginstr=40 but %lu\n",strlen(temp_data.str_hb));
      return 0;
    }
if((param->i_typecalc!=REQ_A)&&(param->i_typecalc!=REQ_B)) fprintf(fileout,"%lli\x09%s\x09 0\n",count_step,temp_data.str_hb);
    for(ii=0;ii<20;ii++)
    {
      strncpy(str_byte,temp_data.str_hb+ii*2,2);
      u_byte=strtol(str_byte,&pEnd,16);
//      u_byte=strtol(str_sb.substr(ii*2,2).c_str(),&pEnd,16);
//      printf("%d byte = %X\n",ii,u_byte);
      memset(&vchSecret_z[ii+12],u_byte, 1);
    }
//   str_sb = (const char*) argv[2];
    count_calc=temp_data.diff;
    printw("count zero=%lli\n", count_calc);

//t  pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
//t  group = EC_KEY_get0_group(pkey);
 // pgen = EC_GROUP_get0_generator(group);
//t  EC_KEY_precompute_mult(pkey,ctx);
//t  priv_key=BN_new();
//t  pub_key = EC_POINT_new(group);
  pub_key_t1 = EC_POINT_new(group);
  pub_key_t2 = EC_POINT_new(group);

  unsigned char hash1[SHA256_DIGEST_LENGTH];

  time_t t_start = time(NULL);
  time_t t_end ;

  long long tt1;
  std::vector<unsigned char> vchPubKey(33, 0);
  unsigned char* pbegin = &vchPubKey[0];

  do
  {
#ifdef performance_test 
 tt1=time_RDTSC();
#endif
//    calc(vchSecret_z,pkey,pub_key,group,priv_key,ctx);
//  BN_CTX *ctx = NULL;



//  BIGNUM *priv_key = 

#ifdef performance_test_c 
long long t1,t2,t3,t4,t5,t6,t7,t8,t9;
time_start();
#endif
//t  BN_bin2bn(vchSecret_z,32,priv_key);
#ifdef performance_test_c
t1 = time_stop();
time_start();
#endif
//t  EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx);
//  EC_POINT_mul_(group, pub_key, priv_key, NULL, NULL, ctx);
//  EC_POINT_add(group,pub_key,pub_key,pgen, ctx);
//  EC_POINT_make_affine(group, pub_key, ctx);
#ifdef performance_test_c
t2 = time_stop();
time_start();
#endif

  EC_POINT_add(group, pub_key_t1,MPoint[7*CountR_CL+((*((unsigned int*)(&vchSecret_z[12])))&0xfffff)], MPoint[6*CountR_CL+(((*((unsigned int*)(&vchSecret_z[14])))>>4)&0xfffff)],ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[5*CountR_CL+((*((unsigned int*)(&vchSecret_z[17])))&0xfffff)],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[4*CountR_CL+(((*((unsigned int*)(&vchSecret_z[19])))>>4)&0xfffff)],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[3*CountR_CL+((*((unsigned int*)(&vchSecret_z[22])))&0xfffff)],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[2*CountR_CL+(((*((unsigned int*)(&vchSecret_z[24])))>>4)&0xfffff)],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[CountR_CL+((*((unsigned int*)(&vchSecret_z[27])))&0xfffff)],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[(((*((unsigned int*)(&vchSecret_z[29])))>>4)&0xfffff)],pub_key_t2,ctx);

/*
  EC_POINT_add(group, pub_key_t1,MPoint[CountR+*(unsigned short*)(&vchSecret_z[28])], MPoint[*(unsigned short*)(&vchSecret_z[30])],ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[2*CountR+*(unsigned short*)(&vchSecret_z[26])],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[3*CountR+*(unsigned short*)(&vchSecret_z[24])],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[4*CountR+*(unsigned short*)(&vchSecret_z[22])],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[5*CountR+*(unsigned short*)(&vchSecret_z[20])],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[6*CountR+*(unsigned short*)(&vchSecret_z[18])],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[7*CountR+*(unsigned short*)(&vchSecret_z[16])],pub_key_t2,ctx);
  EC_POINT_add(group, pub_key_t2,MPoint[8*CountR+*(unsigned short*)(&vchSecret_z[14])],pub_key_t1,ctx);
  EC_POINT_add(group, pub_key_t1,MPoint[9*CountR+*(unsigned short*)(&vchSecret_z[12])],pub_key_t2,ctx);
*/
//  EC_KEY_set_private_key(pkey,priv_key);
#ifdef performance_test_c
t3 = time_stop();
time_start();
#endif
//t  EC_KEY_set_public_key(pkey,pub_key);
#ifdef performance_test_c
t4 = time_stop();
time_start();
#endif
//  EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);
#ifdef performance_test_c
t5 = time_stop();
time_start();
#endif
//tint len = EC_POINT_point2oct(group, pub_key,POINT_CONVERSION_COMPRESSED,pbegin,33,ctx);

EC_POINT_point2oct(group, pub_key_t1,POINT_CONVERSION_COMPRESSED,pbegin,33,ctx);
//  i2o_ECPublicKey(pkey, &pbegin);
#ifdef performance_test_c
t6 = time_stop();
time_start();
#endif
  SHA256(&vchPubKey[0], vchPubKey.size(), hash1);
#ifdef performance_test_c
t7 = time_stop();
time_start();
#endif
  RIPEMD160(hash1, sizeof(hash1), &vchSecret_z[12]);
#ifdef performance_test_c
t8 = time_stop();
t9=t1+t2+t3+t4+t5+t6+t7+t8;
printf("1-%lli-2--%lli-3--%lli-4--%lli-5--%lli-6--%lli-7--%lli-8--%lli-S--%lli\n",t1,t2,t3,t4,t5,t6,t7,t8,t9);
printf("1-(%lli)-2--(%lli)-3--(%lli)-4--(%lli)-5--(%lli)-6--(%lli)-7--(%lli)-8--(%lli)-S--%lli\n",(t1*100)/t9,(t2*100)/t9,(t3*100)/t9,(t4*100)/t9,(t5*100)/t9,(t6*100)/t9,(t7*100)/t9,(t8*100)/t9,t9);
//printf("%i\n",len);
#endif
#ifdef performance_test 
tt1 = time_RDTSC()-tt1;
printf("calc-%lli\n",tt1);
#endif
#ifndef  test_
    if(memcmp(vchSecret_z,&vchSecret_z[12],count_calc)==0)
#endif
    {
      fprintf(fileout,"%lli\x09",count_step);
      sprintf(temp_data.str_nb,"%lli",count_step);
      temp_data.str_hb[0]=0;
      for(ii=0;ii<20;ii++)
      {
        fprintf(fileout,"%02x",vchSecret_z[12+ii]);
        sprintf(str_byte,"%02x",vchSecret_z[12+ii]);
        strcat(temp_data.str_hb,str_byte);
      }
      param->pq->WriteQ(&temp_data);
      sem_post(param->psem_sql);
      t_end = time(NULL);
      fprintf(fileout,"\x09%ld",t_end-t_start);
      if(t_end-t_start!=0) fprintf(fileout,"\x09%d",(int)((count_step-old_count_step)/(t_end-t_start)));
      old_count_step=count_step;
      fprintf(fileout,"\n");
      t_start=t_end;
      if((param->i_typecalc==REQ_A)||(param->i_typecalc==REQ_B)||(vchSecret_z[12+count_calc]==0)) break;
    }
    count_step++;
  }
#ifndef  test_
while(count_calc>0);
#else
while((count_calc>0)&&(count_step<10));
#endif
//    EC_POINT_free(pub_key);
//t    BN_CTX_free(ctx);
//    BN_free(priv_key);
/*
      for(ii=0;ii<20;ii++)
      {
    printf("%02x",vchSecret_z[ii+12]);
      }
      printf("\n");
*/
};

/*
void init_table()
{
  int iCountB,ii;
  BIGNUM *priv_key;
  unsigned char init_str[32];

  memset(&init_str[0], 0, 32);

  priv_key=BN_new();
  pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
  group = EC_KEY_get0_group(pkey);
  EC_KEY_precompute_mult(pkey,ctx);

  for(iCountB=0;iCountB<CountC;iCountB++)
  { 
      printf(" %d\n",iCountB);
      for(ii=0;ii<CountR;ii++)
      {
        MPoint[iCountB*CountR+ii] = EC_POINT_new(group);
        memcpy(&init_str[31-iCountB*2-1], (unsigned short*)((char*)&ii), 2);
        BN_bin2bn(init_str,32,priv_key);
        EC_POINT_mul(group, MPoint[iCountB*CountR+ii], priv_key, NULL, NULL, ctx);
        EC_POINT_make_affine(group,MPoint[iCountB*CountR+ii], ctx);
      }
//      EC_POINTs_make_affine(group,CountR,&MPoint[iCountB][0], ctx);
      memset(&init_str[31-iCountB*2-1],0,2);
//      printf("\n");
  }
  BN_free(priv_key);
}
*/

void *f_thr_calc_cl(void *arg)
{
#ifdef OCL_CLIENT

  time_t t_start = time(NULL);
  time_t t_f ;
  time_t t_end ;


  unsigned int iCountData=0;
//  unsigned int ui_cache,ui_cache_min;
  unsigned int ui_cache,ui_get_cache;
  unsigned int ui_indr;
  unsigned long long count_step=0;
  unsigned long long count_step_end=0;
  unsigned long long count_local;
  int ii,iii;
  char str_byte[3];

  unit_data temp_data;
  char sNameFile[100];
  FILE* fileout = NULL;
  sprintf(sNameFile,"calc_thr_%llX.log",((calc_thr_param*)arg)->id_thr);
  fileout = fopen(sNameFile, "a");

  if (fileout) setbuf(fileout, NULL); // unbuffered

/*
  fprintf(fileout,"IDS=");
  for(ii=0;ii<16;ii++)
    fprintf(fileout,"%02X ",(((calc_thr_param*)arg)->pcl->GetIDS())[ii]);
  fprintf(fileout,"\n");
*/
  if(((calc_thr_param*)arg)->id_thr>0) fprintf(fileout,"FREQ=%u\n",((calc_thr_param*)arg)->pcl->GetFreq(((calc_thr_param*)arg)->id_thr-1));

    temp_data.iId=((calc_thr_param*)arg)->id_thr; 
    temp_data.bCommand=((calc_thr_param*)arg)->i_typecalc; 
    temp_data.psem_calc=((calc_thr_param*)arg)->psem_calc; 
    if(((calc_thr_param*)arg)->id_thr==0)
    {
        //Calc in main summ count for all thread
        ((unsigned int*)temp_data.str_ch)[0] = 1.1*((calc_thr_param*)arg)->i_countcalc; //+10% or biger
//	ui_cache_min = (unsigned int)(0.05*((calc_thr_param*)arg)->i_countcalc);
	
//        ((calc_thr_param*)arg)->pq_thr->SetThreshold((unsigned int)(0.05*((calc_thr_param*)arg)->i_countcalc));
        fprintf(fileout,"ALLDATA count=%i thrid=%llX\n",((unsigned int*)temp_data.str_ch)[0],((calc_thr_param*)arg)->id_thr);
        //Calc in main summ count for all thread
        ((calc_thr_param*)arg)->pq->WriteQ(&temp_data);
	sem_post(((calc_thr_param*)arg)->psem_sql);
    }
    iCountData = ((calc_thr_param*)arg)->pcl->GetDataNumber(); //calc exclusive for every thread 
    fprintf(fileout,"DATA count=%d thrid=%llX\n",iCountData,((calc_thr_param*)arg)->id_thr);
    while(iCountData--)
    {
    	sem_wait(((calc_thr_param*)arg)->psem_calc);
	if(((calc_thr_param*)arg)->pq_thr->ReadQ(&temp_data))
	{
            fprintf(fileout,"number=%d\x09receive %s\x09%s\x09%s\n",iCountData,temp_data.str_ch,temp_data.str_nb,temp_data.str_hb);
	    ((calc_thr_param*)arg)->pcl->PutData(iCountData,temp_data);
//prepare data for main cicle
//		    temp_data.bCommand=SEND_W; 
//		    calc_main(temp_data,((calc_thr_param*)arg),fileout);
	}
	else
	{
	    fprintf(fileout,"!!!!calc thrid=%llX receive not for\n",((calc_thr_param*)arg)->id_thr);
	}
    }
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if(((calc_thr_param*)arg)->id_thr==0)
    {
      ((calc_thr_param*)arg)->pq_thr->SetThreshold((unsigned int)(0.05*((calc_thr_param*)arg)->i_countcalc));
    }
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

//    fprintf(fileout,"MAIN Starting !!!\n");
    while(1)
    {
	if(count_step==0)
	{
            fprintf(fileout,"count_step==0\n");
	    t_start = time(NULL);
	    t_f = time(NULL);
	}
	((calc_thr_param*)arg)->pcl->Run();
//	((calc_thr_param*)arg)->pcl->GetNumberResult();
	ui_indr = ((calc_thr_param*)arg)->pcl->GetNumberResult();
//        fprintf(fileout,"indr=%d count_step=%llu\n",ui_indr,count_step);
	for(ii=0;ii<ui_indr;ii++)
        {
//        fprintf(fileout,"INDEX=%d\n",((calc_thr_param*)arg)->pcl->GetIndR(ii));

//	    temp_data.str_hb[0]=0;
//	    count_local = count_step-((calc_thr_param*)arg)->pcl->GetRData_(((calc_thr_param*)arg)->pcl->GetIndR(ii))[0];
//	    sprintf(temp_data.str_nb,"%llu",count_local);
//	    sprintf(temp_data.str_ch,"%llu",((calc_thr_param*)arg)->pcl->GetRData_(((calc_thr_param*)arg)->pcl->GetIndR(ii))[1]);
	    //it`s ok when count_step over 0xffffffffffffffff 

	    ((calc_thr_param*)arg)->pcl->GetData(((calc_thr_param*)arg)->pcl->GetIndR(ii),temp_data,count_step);

	    fprintf(fileout,"(%llu)%s\x09%s\x09",count_step,temp_data.str_nb,temp_data.str_ch);
	    fprintf(fileout,"%s",temp_data.str_hb);
/*
	    for(int iii=0;iii<20;iii++)
	    {
	        sprintf(str_byte,"%02x",((calc_thr_param*)arg)->pcl->GetRData(((calc_thr_param*)arg)->pcl->GetIndR(ii))[iii]);
    		strcat(temp_data.str_hb,str_byte);
	    }
*/


	    temp_data.iId=((calc_thr_param*)arg)->id_thr; 
	    temp_data.bCommand=SEND_W; 
	    ((calc_thr_param*)arg)->pq->WriteQ(&temp_data);
    	    sem_post(((calc_thr_param*)arg)->psem_sql);

    	    if((ui_get_cache=((calc_thr_param*)arg)->pq_thr->ReadQ(&temp_data))>0)
	    {
               fprintf(fileout,"\x09PUT %s",temp_data.str_ch);
	      ((calc_thr_param*)arg)->pcl->PutData(((calc_thr_param*)arg)->pcl->GetIndR(ii),temp_data,count_step+1);
	    }
	    else
	    {
		fprintf(fileout,"!!!!calc thrid=%llX receive not for\n",((calc_thr_param*)arg)->id_thr);
	    }

	    t_end = time(NULL);
	    fprintf(fileout,"\x09%ld",t_end-t_start);
	    count_step_end=count_step-count_step_end;

    	    if(t_end-t_start!=0) fprintf(fileout,"\x09%d(%lu)",(int)((count_step_end)/(t_end-t_start)),(int)((count_step_end)/(t_end-t_start))*((calc_thr_param*)arg)->pcl->GetDataNumber());
    	    if(t_end-t_f!=0) fprintf(fileout,"\x09%lu",(int)((count_step)/(t_end-t_f))*((calc_thr_param*)arg)->pcl->GetDataNumber());
    	    fprintf(fileout,"\n");
	    count_step_end = count_step;
	    t_start = t_end;

//	    if(((calc_thr_param*)arg)->id_thr==0)
//	    {
//		fprintf(fileout,"cache=%d cache_min=%d\n",ui_cache,ui_cache_min);
//		if(ui_cache<ui_cache_min)
		if(ui_get_cache!=1)
		{
		    ui_cache = ((calc_thr_param*)arg)->pq_thr->GetCountUse();
		    if((ui_get_cache==3)||(ui_get_cache==0))
		    {
	              fprintf(fileout,"CACHE=%d repeat REQ\n",ui_cache);
		    }
		    else
		    {
		      temp_data.iId=((calc_thr_param*)arg)->id_thr; 
		      temp_data.bCommand=((calc_thr_param*)arg)->i_typecalc; 
		      temp_data.psem_calc=((calc_thr_param*)arg)->psem_calc; 
//	              ((unsigned int*)temp_data.str_ch)[0] = 0.1*((calc_thr_param*)arg)->i_countcalc; //+10% or biger
		      ((unsigned int*)temp_data.str_ch)[0] = ((calc_thr_param*)arg)->pq_thr->GetThreshold()*2;
	              fprintf(fileout,"CACHE=%d GET CACHE count=%i\n",ui_cache,((unsigned int*)temp_data.str_ch)[0]);
	              ((calc_thr_param*)arg)->pq->WriteQ(&temp_data);
		      sem_post(((calc_thr_param*)arg)->psem_sql);
		    }
		}
//	    }
	}
	count_step++;
    }
#endif
}


void *f_thr_calc_cache(void *arg)
{

  unsigned int ui_cache,ui_get_cache;
//,ui_cache_min;

  unit_data temp_data;
  char sNameFile[100];
  FILE* fileout = NULL;
  sprintf(sNameFile,"calc_thr_%llX.log",((calc_thr_param*)arg)->id_thr);
  fileout = fopen(sNameFile, "a");

  if (fileout) setbuf(fileout, NULL); // unbuffered

    temp_data.iId=((calc_thr_param*)arg)->id_thr; 
    temp_data.bCommand=((calc_thr_param*)arg)->i_typecalc; 
    temp_data.psem_calc=((calc_thr_param*)arg)->psem_calc; 
    if(((calc_thr_param*)arg)->id_thr==0)
    {
        //Calc in main summ count for all thread
        ((unsigned int*)temp_data.str_ch)[0] = ((calc_thr_param*)arg)->i_countcalc; //+10% or biger
//	ui_cache_min = (unsigned int)(0.1*((calc_thr_param*)arg)->i_countcalc);
        ((calc_thr_param*)arg)->pq_thr->SetThreshold((unsigned int)(0.1*((calc_thr_param*)arg)->i_countcalc));
        fprintf(fileout,"ALLDATA count=%i thrid=%llX\n",((unsigned int*)temp_data.str_ch)[0],((calc_thr_param*)arg)->id_thr);
        //Calc in main summ count for all thread
        ((calc_thr_param*)arg)->pq->WriteQ(&temp_data);
	sem_post(((calc_thr_param*)arg)->psem_sql);
    }
  while(1)
  {
    sem_wait(((calc_thr_param*)arg)->psem_calc);
    if((ui_get_cache=((calc_thr_param*)arg)->pq_thr->ReadQ(&temp_data))>0)
    {
	fprintf(fileout,"receive %s\x09%s\x09%s\n",temp_data.str_ch,temp_data.str_nb,temp_data.str_hb);
	temp_data.bCommand=SEND_W; 
        temp_data.iId=((calc_thr_param*)arg)->id_thr; 
	calc_main(temp_data,((calc_thr_param*)arg),fileout);
    }
    else
    {
	fprintf(fileout,"!!!!calc thrid=%llX receive not for\n",((calc_thr_param*)arg)->id_thr);
    }
//    if(((calc_thr_param*)arg)->id_thr==0)
//    {
//		fprintf(fileout,"cache=%d cache_min=%d\n",ui_cache,ui_cache_min);
//	if(ui_cache<ui_cache_min)
	if(ui_get_cache!=1)
	{
    	    ui_cache = ((calc_thr_param*)arg)->pq_thr->GetCountUse();
	    if((ui_get_cache==3)||(ui_get_cache==0))
	    {
	      fprintf(fileout,"CACHE=%d repeat REQ\n",ui_cache);
	    }
	    else
	    {
		temp_data.iId=((calc_thr_param*)arg)->id_thr; 
		temp_data.bCommand=((calc_thr_param*)arg)->i_typecalc; 
		temp_data.psem_calc=((calc_thr_param*)arg)->psem_calc; 
//		((unsigned int*)temp_data.str_ch)[0] = ((calc_thr_param*)arg)->i_countcalc; 
		((unsigned int*)temp_data.str_ch)[0] = ((calc_thr_param*)arg)->pq_thr->GetThreshold()*10;
		fprintf(fileout,"CACHE=%d GET CACHE count=%i\n",ui_cache,((unsigned int*)temp_data.str_ch)[0]);
		((calc_thr_param*)arg)->pq->WriteQ(&temp_data);
		sem_post(((calc_thr_param*)arg)->psem_sql);
	    }
	}
//    }
  }
}

void *f_thr_calc(void *arg)
{
  unit_data temp_data;
  char sNameFile[100];
  FILE* fileout = NULL;
  sprintf(sNameFile,"calc_thr_%llX.log",((calc_thr_param*)arg)->id_thr);
  fileout = fopen(sNameFile, "a");

  if (fileout) setbuf(fileout, NULL); // unbuffered

  while(1)
  {
	temp_data.iId=((calc_thr_param*)arg)->id_thr; 
        temp_data.bCommand=((calc_thr_param*)arg)->i_typecalc; 
//      printw("In calc thread  Run calc thrid=%d\n",((calc_thr_param*)arg)->id_thr);
        fprintf(fileout,"In calc thread  Run calc thrid=%llX,psem_calc=%p\n",((calc_thr_param*)arg)->id_thr,((calc_thr_param*)arg)->psem_calc);

        temp_data.psem_calc=((calc_thr_param*)arg)->psem_calc; 
        ((calc_thr_param*)arg)->pq->WriteQ(&temp_data);
        sem_post(((calc_thr_param*)arg)->psem_sql);
        sem_wait(((calc_thr_param*)arg)->psem_calc);
	if(((calc_thr_param*)arg)->pq_thr->ReadQ(&temp_data,((calc_thr_param*)arg)->id_thr))
	{
            fprintf(fileout,"calc thrid=%llX receive work diff=%d %s %s %s\n",((calc_thr_param*)arg)->id_thr,temp_data.diff,temp_data.str_ch,temp_data.str_nb,temp_data.str_hb);
	    temp_data.bCommand=SEND_W; 
	    calc_main(temp_data,((calc_thr_param*)arg),fileout);
	}
	else
	{
	    fprintf(fileout,"!!!!calc thrid=%llX receive not for\n",((calc_thr_param*)arg)->id_thr);
	}
  }
}
