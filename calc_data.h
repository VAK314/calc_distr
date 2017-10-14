#include <openssl/ecdsa.h> 
#include <openssl/obj_mac.h> //for NID_secp256k1

//??????
//#include "" NOOOO declarate in this header file.....
//#define DATA_FILE "/bin/data.bin"
#define DATA_FILE "data.bin"
#define CountR_CL  		256*256*16
#define CountC_CL  		8 //segment of table
#define CountKEY 		2
#define LengthKEY  		32
#define COUNT_PRECOMP_DATA   CountR_CL*LengthKEY*CountKEY*CountC_CL

extern  EC_KEY* pkey;
extern  const EC_GROUP *group;
extern  BN_CTX *ctx;

struct ec_point_st {
    const EC_METHOD *meth;
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;
    int Z_is_one;
};

class CCD_
{
private:
  unsigned char* cData;
  unsigned char* cDataZ;
  bool save_data();
  bool pre_comp_data();
public:
  CCD_();
  ~CCD_(){delete[] cData; delete[] cDataZ;};

  bool load_data();
  unsigned char * get_p_precom(){if(load_data()) return cData; else return NULL;};
  void init_ECtable(EC_POINT ** MPoint);
};
