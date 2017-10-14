#include "cl_cl.h"
#include <fstream>
#include <string.h>
#include <math.h> 

#include <stdio.h>


#include <openssl/ecdsa.h>
#include <openssl/ec.h> // for EC_KEY definition
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

using namespace std;


long long TimeValue=0;

unsigned long long time_RDTSC()

{ union ticks

  { unsigned long long tx;

    struct dblword { long tl,th; } dw; // little endian

  } t;

  asm("rdtsc\n": "=a"(t.dw.tl),"=d"(t.dw.th));

  return t.tx;

} // for x86 only!

void time_start() { TimeValue=time_RDTSC(); }

long long time_stop() { return time_RDTSC()-TimeValue; }

/*
struct ec_point_st {
    const EC_METHOD *meth;
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;
    int Z_is_one;
};
*/
typedef struct ec_extra_data_st {
    struct ec_extra_data_st *next;
    void *data;
    void *(*dup_func)(void *);
    void (*free_func)(void *);
    void (*clear_free_func)(void *);
} EC_EXTRA_DATA; /* used in EC_GROUP */

struct ec_group_st {
    const EC_METHOD *meth;

    EC_POINT *generator; /* optional */
    BIGNUM order, cofactor;

    int curve_name;/* optional NID for named curve */
    int asn1_flag; /* flag to control the asn1 encoding */
    point_conversion_form_t asn1_form;

    unsigned char *seed; /* optional seed for parameters (appears in ASN1) */
    size_t seed_len;

    EC_EXTRA_DATA *extra_data; /* linked list */

    /* The following members are handled by the method functions,
     * even if they appear generic */
    
    BIGNUM field; /* Field specification.
                   * For curves over GF(p), this is the modulus;
                   * for curves over GF(2^m), this is the 
                   * irreducible polynomial defining the field.
                   */

    int poly[6]; /* Field specification for curves over GF(2^m).
                  * The irreducible f(t) is then of the form:
                  *     t^poly[0] + t^poly[1] + ... + t^poly[k]
                  * where m = poly[0] > poly[1] > ... > poly[k] = 0.
                  * The array is terminated with poly[k+1]=-1.
                  * All elliptic curve irreducibles have at most 5
                  * non-zero terms.
                  */

    BIGNUM a, b; /* Curve coefficients.
                  * (Here the assumption is that BIGNUMs can be used
                  * or abused for all kinds of fields, not just GF(p).)
                  * For characteristic  > 3,  the curve is defined
                  * by a Weierstrass equation of the form
                  *     y^2 = x^3 + a*x + b.
                  * For characteristic  2,  the curve is defined by
                  * an equation of the form
                  *     y^2 + x*y = x^3 + a*x^2 + b.
                  */

    int a_is_minus3; /* enable optimized point arithmetics for special case */

    void *field_data1; /* method-specific (e.g., Montgomery structure) */
    void *field_data2; /* method-specific */
    int (*field_mod_func)(BIGNUM *, const BIGNUM *, const BIGNUM *,	BN_CTX *); /* method-specific */
} /* EC_GROUP */;



void CCl_::err_check( int err, const char * err_str) {
  if (err != CL_SUCCESS )
  {
    printf("Error %s=%d\n",err_str,err);
    exit(-1);
  }
}

/*
bool CCl_::save_data()
{
  ofstream outputFile(DATA_FILE,std::ofstream::binary);
  outputFile.write((char*)cData, COUNT_PRECOMP_DATA);
  outputFile.close();
  return true;
}

bool CCl_::load_data()
{
  ifstream inputFile( DATA_FILE, ios::in | ios::binary );
  if( !inputFile )
  {
    printf("File data.bin lost begin precomute data\n");
    if(!pre_comp_data()) return false;
  }
  else
  {
    printf("File data.bin found!!! Begin read data\n");
    ifstream::pos_type size = 0;
    if( inputFile.seekg(0, ios::end) )
    {
       size = inputFile.tellg();
       if(size!=COUNT_PRECOMP_DATA)
       {
          printf("wrong file size\n");
          inputFile.close();
          if(!pre_comp_data()) return false;
       }
       else
       {
         if( size && inputFile.seekg(0, std::ios::beg) )
         {
           inputFile.read((char*)cData, size);
           inputFile.close();
         }
       }
    }
  }
  return true;
}

bool CCl_::pre_comp_data()
{

  const EC_GROUP *group;
  const EC_POINT *pgen;

  uint iCountB,ii,ii4,iStep,iShift;
  EC_KEY* pkey;
  BIGNUM *priv_key;
  BN_CTX *ctx = NULL;
  unsigned char init_str[32];
    memset(cData,0,COUNT_PRECOMP_DATA);
    memset(&init_str[0], 0, 32);

    priv_key=BN_new();
    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    group = EC_KEY_get0_group(pkey);
    EC_POINT *pub_key = NULL;
    pub_key =EC_POINT_new(group);

    for(iCountB=0;iCountB<CountC_CL;iCountB++)
    {
      printf(" %d\n",iCountB);
      if(iCountB%2==0)
      {
        iStep=29-iCountB*5/2;
        iShift=4;
      }
      else
      {
        iStep=29-(iCountB*5-1)/2;
        iShift=0;
      }
      for(ii=1;ii<CountR_CL;ii++)
      {
        ii4=ii<<iShift;
        memcpy(&init_str[iStep],((char*)&ii4), 3);
        BN_bin2bn(init_str,32,priv_key);
        EC_POINT_mul(group,pub_key, priv_key, NULL, NULL, ctx);
        EC_POINT_make_affine(group,pub_key, ctx);
        memcpy(cData+(iCountB*CountR_CL+ii)*CountKEY*LengthKEY,pub_key->X.d,32);
        memcpy(cData+((iCountB*CountR_CL+ii)*CountKEY+1)*LengthKEY,pub_key->Y.d,32);
      }
      memset(&init_str[iStep],0,3);
    }
    BN_free(priv_key);
    printf("end of prepeare datat ");
    if(save_data()) return true;
    return false;
}
*/
void CCl_::printf_dev_type(cl_device_type dt)
{
  switch(dt)
  {
    case CL_DEVICE_TYPE_CPU:
	printf("Device type=CL_DEVICE_TYPE_CPU\n");
    break;
    case CL_DEVICE_TYPE_GPU:
	printf("Device type=CL_DEVICE_TYPE_GPU\n");
    break;
    case CL_DEVICE_TYPE_ACCELERATOR:
	printf("Device type=CL_DEVICE_TYPE_ACCELERATOR\n");
    break;
    case CL_DEVICE_TYPE_DEFAULT:
	printf("Device type=CL_DEVICE_TYPE_DEFAULT\n");
    break;
    case CL_DEVICE_TYPE_ALL:
	printf("Device type=CL_DEVICE_TYPE_ALL\n");
    break;
    default:
	printf("Unknown device type\n");
  }
}

unsigned char GetGPUCount()
{
  cl_platform_id platform_id;
  cl_uint ret_num_platforms;
  cl_uint nd;
  cl_int res;


  clGetPlatformIDs( 1, &platform_id, &ret_num_platforms );
  res = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 0, NULL, &nd);
  if (res != CL_SUCCESS) {
	printf( "clGetDeviceIDs ERR\n");
	return false;
  }
  return nd;
}

unsigned char *  CCl_::GetIDS()
{
    return  (unsigned char *)ids;
}

unsigned int  CCl_::GetFreq(unsigned int ui_number_dev)
{
    cl_int ret;
    cl_uint val;
    size_t size_ret;
    ret = clGetDeviceInfo(ids[ui_number_dev], CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof(val), &val, &size_ret);
    if (ret != CL_SUCCESS) {
	printf("CL_DEVICE_MAX_COMPUTE_UNITS - err");
    }
    return val;
}


bool CCl_::initCL(cl_device_type cl_dt,unsigned int ui_number_dev,unsigned int blk_number,unsigned int gl_blk_number,unsigned int r_number)
{
//  cl_uint nd;
  cl_int res;
//  cl_device_id *ids;

  char buf_opt[255];

  ROUND_NUMBER		= r_number;

  unsigned int  WORK_GR_SIZE		= BLOCK_SIZE*blk_number;
  unsigned int  WORK_GLOBAL_GR_SIZE	= WORK_GR_SIZE*gl_blk_number;
  unsigned int  SECOND_GR_SIZE		= (BLOCK_SIZE-BLOCK_SIZE_F)*blk_number*gl_blk_number;
  unsigned int  DATA_NUMBER		= (ROUND_NUMBER-2)*blk_number*gl_blk_number;

  uiResult_ind = new unsigned int[DATA_NUMBER+2];

  err = clGetPlatformIDs( 1, &platform_id, &ret_num_platforms );
  err_check(err,"clGetPlatformIDs");
  printf_dev_type(cl_dt);

  res = clGetDeviceIDs(platform_id, cl_dt, 0, NULL, &nd);
  if (res != CL_SUCCESS) {
	printf( "clGetDeviceIDs ERR\n");
	return false;
  }
  if(nd<=ui_number_dev)
  {
    	printf( "wrong device number ERR\n");
	return false;
  }
  ids = (cl_device_id *) malloc(nd * sizeof(*ids));

  err = clGetDeviceIDs( platform_id, cl_dt, nd,  ids, NULL );
  err_check(err,"clGetDeviceIDs");
  context = clCreateContext( NULL, 1, &ids[ui_number_dev], NULL, NULL, &err );
  err_check(err,"clCreateContext"); 
  command_queue = clCreateCommandQueue( context, ids[ui_number_dev], 0, &err );
  err_check( err, "clCreateCommandQueue" );




  wgs_c[0]=WORK_GLOBAL_GR_SIZE;
  witems_c[0]=WORK_GR_SIZE;

    cl_int ret;
    cl_uint val;
    size_t size_ret;
    ret = clGetDeviceInfo(ids[ui_number_dev], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(val), &val, &size_ret);
    if (ret != CL_SUCCESS) {
	printf( "CL_DEVICE_MAX_COMPUTE_UNITS - err");
    }
    printf("CL_DEVICE_MAX_COMPUTE_UNITS=%u\n",val);

  wgs_h[0]=DATA_NUMBER;
  if(cl_dt == CL_DEVICE_TYPE_CPU)
  {
     witems_h[0]= DATA_NUMBER/val/2;
    if(witems_h[0]>1024)  witems_h[0]=1024;
  }
  else
  {
     witems_h[0]= sqrt(DATA_NUMBER);
    if(witems_h[0]>256)  witems_h[0]=256;
  }
  sprintf(buf_opt, "-D WORKSIZE_M=%lu -D WORKSIZE_H=%lu",witems_c[0],witems_h[0]);


  cmBegin_data = clCreateBuffer( context, CL_MEM_SET_WR, LengthHASH*DATA_NUMBER, NULL, &err );
  err_check( err, "cmBegin_data" );
/*
memory
  cData_begin=(unsigned char *)clEnqueueMapBuffer( command_queue,   // Corresponding command queue
                                            cmBegin_data,     // Buffer to be mapped
                                            CL_TRUE,         // block_map, CL_TRUE: can't be unmapped before at least 1 read 
                                            CL_MAP_READ|CL_MAP_WRITE,    // mapped for reading or writing?
                                            0,               // offset
                                            LengthHASH*DATA_NUMBER,         // number of bytes mapped
                                            0,               // number of events in the wait list  
                                            NULL,            // event wait list  
                                            NULL,            // event
                                            &err );          // error
*/
  err_check( err, "map cmBegin_data" );

  ullData_add = new unsigned long long[DATA_NUMBER*2];

  cmBN_data = clCreateBuffer( context, CL_MEM_HOST_NO_ACCESS|CL_MEM_READ_WRITE, LengthKEY*3*DATA_NUMBER, NULL, &err );
  err_check( err, "cmBN_data" );

  cmHash256_data = clCreateBuffer( context, CL_MEM_HOST_NO_ACCESS|CL_MEM_READ_WRITE, LengthHASH256*DATA_NUMBER, NULL, &err );
  err_check( err, "cmBN_data" );

  cmPreComp_data = clCreateBuffer( context, CL_MEM_SET_R, COUNT_PRECOMP_DATA, NULL, &err );
  err_check( err, "cmPreComp_data" );

  err = clEnqueueWriteBuffer(command_queue, cmPreComp_data, CL_TRUE, 0, COUNT_PRECOMP_DATA, cData, 0, NULL, NULL);
  err_check( err, "map cmPreComp_data" );
/*
  cData=(unsigned char *)clEnqueueMapBuffer( command_queue,   // Corresponding command queue
                                            cmPreComp_data,     // Buffer to be mapped
                                            CL_TRUE,         // block_map, CL_TRUE: can't be unmapped before at least 1 read 
                                            CL_MAP_READ,    // mapped for reading or writing?
                                            0,               // offset
                                            COUNT_PRECOMP_DATA,         // number of bytes mapped
                                            0,               // number of events in the wait list  
                                            NULL,            // event wait list  
                                            NULL,            // event
                                            &err );          // error
err_check( err, "map cmPreComp_data" );
*/
  cmInd_result  = clCreateBuffer( context, CL_MEM_READ_WRITE, sizeof(unsigned int)*(DATA_NUMBER+2), NULL, &err );
  err_check( err, "cmInd_result" );

/*
  cResult_ind=(unsigned char *)clEnqueueMapBuffer( command_queue,   // Corresponding command queue
                                            cmInd_result,     // Buffer to be mapped
                                            CL_TRUE,         // block_map, CL_TRUE: can't be unmapped before at least 1 read 
                                            CL_MAP_READ|CL_MAP_WRITE,    // mapped for reading or writing?
                                            0,               // offset
                                            sizeof(unsigned int)*(DATA_NUMBER+2),         // number of bytes mapped
                                            0,               // number of events in the wait list  
                                            NULL,            // event wait list  
                                            NULL,            // event
                                            &err );          // error
  err_check( err, "map cmInd_result" );
*/

//test GLOBAL DATA  ******************************************************


  cmBN_data_l = clCreateBuffer( context, CL_MEM_HOST_NO_ACCESS|CL_MEM_READ_WRITE,LengthKEY*3*SECOND_GR_SIZE*2, NULL, &err );
  err_check( err, "cmBN_data_l" );

//test 

  ifstream file("cl_8.cl");
  string prog( istreambuf_iterator<char>( file ), ( istreambuf_iterator<char>() ) );
  const char *source_str = prog.c_str();
  program = clCreateProgramWithSource( context, 1, (const char **) &source_str, 0, &err );
  err_check( err, "clCreateProgramWithSource" );

printf("Build options '%s'",buf_opt);
  err = clBuildProgram( program, 1, &ids[ui_number_dev], buf_opt, NULL, NULL );
  err_check( err,"clBuildProgram" );

//printf("clCreateKernel(multi_add_8)\n");


 multi_add_kernel = clCreateKernel( program, "multi_add_8", &err ); err_check( err, "clCreateKernel multi_add_8" );
 get_invers_z_kernel = clCreateKernel( program, "get_invers_z", &err ); err_check( err, "clCreateKernel get_invers z" );
 get_invers_a_kernel = clCreateKernel( program, "get_invers_a", &err ); err_check( err, "clCreateKernel get_invers a" );
 get_invers_b_kernel = clCreateKernel( program, "get_invers_b", &err ); err_check( err, "clCreateKernel get_invers b" );
 get_hash_256_kernel = clCreateKernel( program, "get_hash_256", &err ); err_check( err, "clCreateKernel get_hash_256" );
 get_hash_kernel = clCreateKernel( program, "get_hash", &err ); err_check( err, "clCreateKernel get_hash" );



 cl_ulong L_size;
 cl_ulong P_size;
/*
   clGetKernelWorkGroupInfo(multi_add_kernel,device_id,CL_KERNEL_LOCAL_MEM_SIZE,sizeof(L_size), &L_size, &size_ret);
   clGetKernelWorkGroupInfo(multi_add_kernel,device_id,CL_KERNEL_PRIVATE_MEM_SIZE,sizeof(P_size), &P_size, &size_ret);
printf("multi_add_kernel CL_KERNEL_LOCAL_MEM_SIZE=%ldKb\n",L_size/1024);
printf("multi_add_kernel get_data_8 CL_KERNEL_PRIVATE_MEM_SIZE=%ld\n",P_size);
*/

  err = clSetKernelArg( multi_add_kernel, 0, sizeof( cl_mem ), (void *) &cmBegin_data);
  err_check( err, "clSetKernelArg0 mult" );


  err = clSetKernelArg( multi_add_kernel, 1, sizeof( cl_mem ), (void *) &cmPreComp_data);
  err_check( err, "clSetKernelArg1 mult" );


  err = clSetKernelArg( multi_add_kernel,2, sizeof( cl_mem ), (void *) &cmBN_data);
  err_check( err, "clSetKernelArg2 mult" );

  err = clSetKernelArg( multi_add_kernel, 3, sizeof( cl_mem ), (void *) &cmInd_result);
  err_check( err, "clSetKernelArg3 mult" );

//test GLOBAL DATA  ******************************************************

//for local array init =>  err = clSetKernelArg(multi_add_kernel, 3, LengthKEY*3*SECOND_GR_SIZE*2, NULL);
  err = clSetKernelArg(multi_add_kernel, 4, sizeof( cl_mem ),(void *) &cmBN_data_l);
err_check( err, "clSetKernelArg mult" );

//test GLOBAL DATA  ******************************************************

  err = clSetKernelArg( get_invers_z_kernel, 0, sizeof( cl_mem ), (void *) &cmBN_data);
  err_check( err, "clSetKernelArg0 get_invers z" );

  err = clSetKernelArg( get_invers_a_kernel, 0, sizeof( cl_mem ), (void *) &cmBN_data);
  err_check( err, "clSetKernelArg0 get_invers a" );

  err = clSetKernelArg( get_invers_b_kernel, 0, sizeof( cl_mem ), (void *) &cmBN_data);
  err_check( err, "clSetKernelArg0 get_invers b" );


  err = clSetKernelArg( get_hash_256_kernel, 0, sizeof( cl_mem ), (void *) &cmBN_data);
  err_check( err, "clSetKernelArg0 hash256" );


  err = clSetKernelArg( get_hash_256_kernel, 1, sizeof( cl_mem ), (void *) &cmHash256_data);
  err_check( err, "clSetKernelArg1 get256" );


  err = clSetKernelArg( get_hash_kernel, 0, sizeof( cl_mem ), (void *) &cmHash256_data);
  err_check( err, "clSetKernelArg0 get" );

  err = clSetKernelArg( get_hash_kernel, 1, sizeof( cl_mem ), (void *) &cmBegin_data);
  err_check( err, "clSetKernelArg1 get" );

  err = clSetKernelArg( get_hash_kernel, 2, sizeof( cl_mem ), (void *) &cmInd_result);
  err_check( err, "clSetKernelArg2 get" );

/*
   clGetKernelWorkGroupInfo(multi_add_kernel,device_id,CL_KERNEL_LOCAL_MEM_SIZE,sizeof(L_size), &L_size, &size_ret);
   clGetKernelWorkGroupInfo(multi_add_kernel,device_id,CL_KERNEL_PRIVATE_MEM_SIZE,sizeof(P_size), &P_size, &size_ret);
printf("multi_add_kernel CL_KERNEL_LOCAL_MEM_SIZE=%ldKb\n",L_size/1024);
printf("multi_add_kernel get_data_8 CL_KERNEL_PRIVATE_MEM_SIZE=%ld\n",P_size);
*/


// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TEST
/*
 get_test_kernel = clCreateKernel( program, "get_test", &err ); err_check( err, "clCreateKernel get_hash" );


  size_t wgs_c__[1];
  size_t witems_c__[1];
  char buf_err[256];
  cl_event ev;

  wgs_c__[0]=1;
  witems_c__[0]=1;

  if(cl_dt != CL_DEVICE_TYPE_CPU)
  {
    err=clEnqueueNDRangeKernel( command_queue, get_test_kernel, 1, NULL,wgs_c__ ,NULL, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    sprintf(buf_err,"clWaitForEvents TEST");
    err_check( err, buf_err);
  }
*/
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!TEST


  return true;
}


void CCl_::Run()
{
  char buf_err[256];

  unsigned int i;
  cl_ulong L_size;
  cl_ulong P_size;
  size_t size_ret;

  cl_event ev;

  uiResult_ind[0]=ROUND_NUMBER;
  uiResult_ind[1]=0;
  err = clEnqueueWriteBuffer(command_queue, cmInd_result, CL_TRUE, 0, sizeof(unsigned int)*2, uiResult_ind, 0, NULL, NULL);
  err_check( err, "write cmInd_result");

    err=clEnqueueNDRangeKernel( command_queue, multi_add_kernel, 1, NULL,wgs_c ,witems_c, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    sprintf(buf_err,"clWaitForEvents mul8 wg=%lu",witems_c[0]);
    err_check( err, buf_err);

    err=clEnqueueNDRangeKernel( command_queue, get_invers_z_kernel, 1, NULL,wgs_h ,witems_h, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    err_check( err, "clWaitForEvents invers z" );


    err=clEnqueueNDRangeKernel( command_queue, get_invers_a_kernel, 1, NULL,wgs_h ,witems_h, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    err_check( err, "clWaitForEvents invers a" );

    err=clEnqueueNDRangeKernel( command_queue, get_invers_b_kernel, 1, NULL,wgs_h ,witems_h, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    err_check( err, "clWaitForEvents invers b" );

    err=clEnqueueNDRangeKernel( command_queue, get_hash_256_kernel, 1, NULL,wgs_h ,witems_h, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    err_check( err, "clWaitForEvents hash256" );

    err=clEnqueueNDRangeKernel( command_queue, get_hash_kernel, 1, NULL,wgs_h ,witems_h, 0, 0, &ev );
    err = clWaitForEvents(1, &ev);
    clReleaseEvent(ev);
    err_check( err, "clWaitForEvents hash" );

}


unsigned long CCl_::GetDataNumber()
{
  return wgs_h[0];
}


unsigned int CCl_::GetNumberResult()
{
  unsigned int uiResCount;
  err = clEnqueueReadBuffer(command_queue, cmInd_result, CL_TRUE, sizeof(unsigned int),sizeof(unsigned int)*2, uiResult_ind, 0, NULL, NULL);
  err_check( err, "read cmInd_result");
  if(uiResult_ind[0]>1)
  {
    uiResCount=uiResult_ind[0]+1;
    err = clEnqueueReadBuffer(command_queue, cmInd_result, CL_TRUE, sizeof(unsigned int),sizeof(unsigned int)*uiResCount, uiResult_ind, 0, NULL, NULL);
    err_check( err, "read cmInd_result");
  }
  return uiResult_ind[0];
};


bool CCl_::GetData(unsigned int ui_id_data,unit_data &temp_data,unsigned long long ull_main_count)
{
  unsigned char ucBuf[LengthHASH];
  char str_byte[3];

  sprintf(temp_data.str_nb,"%llu",ull_main_count-ullData_add[ui_id_data*2]);
  sprintf(temp_data.str_ch,"%llu",ullData_add[ui_id_data*2+1]);
  err = clEnqueueReadBuffer(command_queue, cmBegin_data, CL_TRUE,ui_id_data*LengthHASH,LengthHASH, ucBuf,0, NULL, NULL);
  err_check( err, "read cmBegin_data" );
  temp_data.str_hb[0]=0;
  for(int iii=0;iii<20;iii++)
  {
    sprintf(str_byte,"%02x",ucBuf[iii]);
    strcat(temp_data.str_hb,str_byte);
  }
  return true;
}


bool CCl_::PutData(unsigned int ui_id_data,unit_data temp_data,unsigned long long ull_main_count)
{
  unsigned char ucBuf[LengthHASH];
  if(ui_id_data<GetDataNumber())
  { 
//ch__ 20160209
    ullData_add[ui_id_data*2]=ull_main_count-strtoul(temp_data.str_nb,NULL,10);
    ullData_add[ui_id_data*2+1]=strtoul(temp_data.str_ch,NULL,10);
    if(strlen(temp_data.str_hb)<LengthHASH*2)
    {
//      printf("ERRRRRRRRROR len=%lu",strlen(temp_data.str_hb));
      return false;
    }
    for(int i=(LengthHASH-1);i>=0;i--)
    {
	ucBuf[i]=strtol((temp_data.str_hb+i*2),NULL,16);
//cmBegin_data
//	   cData_begin[ui_id_data*LengthHASH+i]=strtol((temp_data.str_hb+i*2),NULL,16);
	temp_data.str_hb[i*2]=0;
    }

    err = clEnqueueWriteBuffer(command_queue, cmBegin_data, CL_TRUE, ui_id_data*LengthHASH, LengthHASH, ucBuf, 0, NULL, NULL);
    err_check( err, "write cmBegin_data" );

    return true;
  }
  return false;
}

bool CCl_::ViewData()
{
}   
 
bool CCl_::relData()
{
  printf("Release!!!\n");


  err = clFlush( command_queue );
  err_check( err, "Flush command_queue" );
  err = clFinish( command_queue );
  err_check( err, "Finish command_queue" );
  err = clReleaseKernel(multi_add_kernel);
  err_check( err, "multi_add_kernel" );
  err = clReleaseMemObject(cmBN_data); 
  err_check( err, "release cmBN_data" );

  err = clReleaseMemObject(cmBN_data_l); 
  err_check( err, "release cmBN_data" );

  err = clReleaseMemObject(cmPreComp_data); 
  err_check( err, "release cmPreComp_data" );

  err = clReleaseMemObject(cmBegin_data); 
  err_check( err, "release cmBegin_data" );

  err = clReleaseCommandQueue( command_queue );
  err_check( err, "relese command_queue" );
  err = clReleaseContext( context );
  err_check( err, "release context" );
  return true;
}
