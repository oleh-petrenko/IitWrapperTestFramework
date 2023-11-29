#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef enum
{
	EUPubKeyUnknown             = 0,
	EUPubKeyDSTU4145            = 1,
	EUPubKeyRSA                 = 2,
	EUPubKeyECDSA				= 4
} EUPublicKeyType;

typedef enum
{
	EUKeyUsageUnknown           = 0,
	EUKeyUsageDigitalSignature  = 0x0001,
	EUKeyUsageNonRepudation     = 0x0002,
	EUKeyUsageKeyAgreement      = 0x0010
} EUKeyUsage;

typedef enum
{
	EUKeysTypeNone					= 0,
	EUKeysTypeDSTUAndECDHWithGOSTs	= 1,
	EUKeysTypeRSAWithSHA			= 2,
	EUKeysTypeECDSAWithSHA			= 4
} EUKeysType;

typedef enum
{
	EUKeysLengthDSUA_None			= 0,
	EUKeysLengthDSUA_191			= 1,
	EUKeysLengthDSUA_257			= 2,
	EUKeysLengthDSUA_307			= 3,
	EUKeysLengthDSUA_File			= 4
} EUKeysLengthDSUA;

typedef enum
{
	EUKeysLengthKEPUA_None			= 0,
	EUKeysLengthKEPUA_257			= 1,
	EUKeysLengthKEPUA_431			= 2,
	EUKeysLengthKEPUA_571			= 3,
	EUKeysLengthKEPUA_File			= 4
} EUKeysLengthKEPUA;

typedef enum
{
	EUKeysLengthDSRSA_None			= 0,
	EUKeysLengthDSRSA_1024			= 1,
	EUKeysLengthDSRSA_2048			= 2,
	EUKeysLengthDSRSA_3072			= 3,
	EUKeysLengthDSRSA_4096			= 4,
	EUKeysLengthDSRSA_File			= 5
} EUKeysLengthDSRSA;

typedef enum
{
	EUKeysLengthDSECDSA_None		= 0,
	EUKeysLengthDSECDSA_192			= 1,
	EUKeysLengthDSECDSA_256			= 2,
	EUKeysLengthDSECDSA_384			= 3,
	EUKeysLengthDSECDSA_521			= 4,
	EUKeysLengthDSECDSA_File		= 5
} EUKeysLengthDSECDSA;

typedef enum
{
	EURequestTypeNone				= 0,
	EURequestTypeDSUA				= 1,
	EURequestTypeKEPUA				= 2,
	EURequestTypeRSA				= 3,
	EURequestTypeECDSA				= 4
} EURequestType;

typedef enum
{
	EUContentEncAlgoGOST28147_CFB		= 2,
	EUContentEncAlgoTDES_CBC			= 4,
	EUContentEncAlgoAES_128_CBC			= 5,
	EUContentEncAlgoAES_192_CBC			= 6,
	EUContentEncAlgoAES_256_CBC			= 7,
	EUContentEncAlgoDSTU7624_256_OFB	= 8,
	EUContentEncAlgoDSTU7624_256_CFB	= 9
} EUContentEncAlgo;

typedef enum
{
	EUSessionEncAlgoGOST28147		= 0,
	EUSessionEncAlgoDSTU7624_256	= 1,
	EUSessionEncAlgoDSTU7624_512	= 2,
	EUSessionEncAlgoDSTU8845_256	= 3,
	EUSessionEncAlgoDSTU8845_512	= 4
} EUSessionEncAlgo;

typedef enum
{
	EUASiCTypeUnknown			= 0,
	EUASiCTypeS					= 1,
	EUASiCTypeE 				= 2
} EUASiCType;

typedef enum
{
	EUASiCSignTypeUnknown		= 0,
	EUASiCSignTypeCAdES			= 1,
	EUASiCSignTypeXAdES			= 2
} EUASiCSignType;

typedef enum
{
	EUCAdESSignLevelUnknown			= 0,
	EUCAdESSignLevel_BES			= 1,
	EUCAdESSignLevel_T				= 4,
	EUCAdESSignLevel_C 				= 8,
	EUCAdESSignLevel_X_Long 		= 16,
	EUCAdESSignLevel_X_Long_Trusted = 128
} EUCAdESSignLevel;

typedef enum
{
	EUXAdESTypeUnknown			= 0,
	EUXAdESTypeDetached			= 1,
	EUXAdESTypeEnveloping		= 2,
	EUXAdESTypeEnveloped 		= 3
} EUXAdESType;

typedef enum
{
	EUXAdESSignLevelUnknown		= 0,
	EUXAdESSignLevelB_B			= 1,
	EUXAdESSignLevelB_T			= 4,
	EUXAdESSignLevelB_LT 		= 16,
	EUXAdESSignLevelB_LTA 		= 32
} EUXAdESSignLevel;

typedef enum
{
	EUPAdESSignLevelUnknown		= 0,
	EUPAdESSignLevelB_B			= 1,
	EUPAdESSignLevelB_T			= 4
} EUPAdESSignLevel;

typedef enum
{
	EUCtxHashAlgoUnknown             = 0,
	EUCtxHashAlgoGOST34311           = 1,
	EUCtxHashAlgoSHA160              = 2,
	EUCtxHashAlgoSHA224              = 3,
	EUCtxHashAlgoSHA256              = 4
} EUCtxHashAlgo;

typedef enum
{
	EUCtxSignAlgoUnknown                = 0,
	EUCtxSignAlgoDSTU4145WithGOST34311  = 1,
	EUCtxSignAlgoRSAWithSHA             = 2,
	EUCtxSignAlgoECDSAWithSHA           = 3
} EUCtxSignAlgo;

@interface EUDataReference : NSObject
@property (nonatomic, strong) NSString *name;
@property (nonatomic, strong) NSData *data;

+ (instancetype) reference:(NSString *) name
					  data:(NSData *) data;
@end

@interface EUCASettings : NSObject
@property (nonatomic, strong) NSArray <NSString *>* issuerCNs;
@property (nonatomic, strong) NSString *address;
@property (nonatomic, strong) NSString *ocspAccessPointAddress;
@property (nonatomic, strong) NSString *ocspAccessPointPort;
@property (nonatomic, strong) NSString *cmpAddress;
@property (nonatomic, strong) NSString *tspAddress;
@property (nonatomic, strong) NSString *tspAddressPort;
@property (nonatomic) BOOL certsInKey;
+ (instancetype) settings:(NSDictionary *) settings;
@end

@interface EUSignInfo : NSObject
@property (nonatomic) BOOL isFilled;

@property (nonatomic, strong) NSString *issuer;
@property (nonatomic, strong) NSString *issuerCN;
@property (nonatomic, strong) NSString *serial;

@property (nonatomic, strong) NSString *subject;
@property (nonatomic, strong) NSString *subjCN;
@property (nonatomic, strong) NSString *subjOrg;
@property (nonatomic, strong) NSString *subjOrgUnit;
@property (nonatomic, strong) NSString *subjTitle;
@property (nonatomic, strong) NSString *subjState;
@property (nonatomic, strong) NSString *subjLocality;
@property (nonatomic, strong) NSString *subjFullName;
@property (nonatomic, strong) NSString *subjAddress;
@property (nonatomic, strong) NSString *subjPhone;
@property (nonatomic, strong) NSString *subjEMail;
@property (nonatomic, strong) NSString *subjDNS;
@property (nonatomic, strong) NSString *subjEDRPOUCode;
@property (nonatomic, strong) NSString *subjDRFOCode;

@property (nonatomic) BOOL isTimeAvail;
@property (nonatomic) BOOL isTimeStamp;
@property (nonatomic, strong) NSDate *time;

@end

@interface EUCertificateInfo : NSObject
@property (nonatomic) BOOL isFilled;

@property (nonatomic) NSInteger version;

@property (nonatomic, strong) NSString *issuer;
@property (nonatomic, strong) NSString *issuerCN;
@property (nonatomic, strong) NSString *serial;

@property (nonatomic, strong) NSString *subject;
@property (nonatomic, strong) NSString *subjCN;
@property (nonatomic, strong) NSString *subjOrg;
@property (nonatomic, strong) NSString *subjOrgUnit;
@property (nonatomic, strong) NSString *subjTitle;
@property (nonatomic, strong) NSString *subjState;
@property (nonatomic, strong) NSString *subjLocality;
@property (nonatomic, strong) NSString *subjFullName;
@property (nonatomic, strong) NSString *subjAddress;
@property (nonatomic, strong) NSString *subjPhone;
@property (nonatomic, strong) NSString *subjEMail;
@property (nonatomic, strong) NSString *subjDNS;
@property (nonatomic, strong) NSString *subjEDRPOUCode;
@property (nonatomic, strong) NSString *subjDRFOCode;

@property (nonatomic, strong) NSString *subjNBUCode;
@property (nonatomic, strong) NSString *subjSPFMCode;
@property (nonatomic, strong) NSString *subjOCode;
@property (nonatomic, strong) NSString *subjOUCode;
@property (nonatomic, strong) NSString *subjUserCode;

@property (nonatomic, strong) NSDate *certBeginTime;
@property (nonatomic, strong) NSDate *certEndTime;
@property (nonatomic) BOOL isPrivKeyTimes;
@property (nonatomic, strong) NSDate *privKeyBeginTime;
@property (nonatomic, strong) NSDate *privKeyEndTime;

@property (nonatomic) NSInteger publicKeyBits;
@property (nonatomic, strong) NSString *publicKey;
@property (nonatomic, strong) NSString *publicKeyID;

@property (nonatomic) BOOL isECDHPublicKey;
@property (nonatomic) NSInteger ecdhPublicKeyBits;
@property (nonatomic, strong) NSString *ecdhPublicKey;
@property (nonatomic, strong) NSString *ecdhPublicKeyID;

@property (nonatomic, strong) NSString *issuerPublicKeyID;

@property (nonatomic, strong) NSString *keyUsage;
@property (nonatomic, strong) NSString *extKeyUsages;
@property (nonatomic, strong) NSString *policies;

@property (nonatomic, strong) NSString *crlDistribPoint1;
@property (nonatomic, strong) NSString *crlDistribPoint2;

@property (nonatomic) BOOL isPowerCert;

@property (nonatomic) BOOL isSubjType;
@property (nonatomic) BOOL isSubjCA;

@end

@interface EUCertificateInfoEx : NSObject
@property (nonatomic) BOOL isFilled;

@property (nonatomic) NSInteger version;

@property (nonatomic, strong) NSString *issuer;
@property (nonatomic, strong) NSString *issuerCN;
@property (nonatomic, strong) NSString *serial;

@property (nonatomic, strong) NSString *subject;
@property (nonatomic, strong) NSString *subjCN;
@property (nonatomic, strong) NSString *subjOrg;
@property (nonatomic, strong) NSString *subjOrgUnit;
@property (nonatomic, strong) NSString *subjTitle;
@property (nonatomic, strong) NSString *subjState;
@property (nonatomic, strong) NSString *subjLocality;
@property (nonatomic, strong) NSString *subjFullName;
@property (nonatomic, strong) NSString *subjAddress;
@property (nonatomic, strong) NSString *subjPhone;
@property (nonatomic, strong) NSString *subjEMail;
@property (nonatomic, strong) NSString *subjDNS;
@property (nonatomic, strong) NSString *subjEDRPOUCode;
@property (nonatomic, strong) NSString *subjDRFOCode;

@property (nonatomic, strong) NSString *subjNBUCode;
@property (nonatomic, strong) NSString *subjSPFMCode;
@property (nonatomic, strong) NSString *subjOCode;
@property (nonatomic, strong) NSString *subjOUCode;
@property (nonatomic, strong) NSString *subjUserCode;

@property (nonatomic, strong) NSDate *certBeginTime;
@property (nonatomic, strong) NSDate *certEndTime;
@property (nonatomic) BOOL isPrivKeyTimes;
@property (nonatomic, strong) NSDate *privKeyBeginTime;
@property (nonatomic, strong) NSDate *privKeyEndTime;

@property (nonatomic) NSInteger publicKeyBits;
@property (nonatomic, strong) NSString *publicKey;
@property (nonatomic, strong) NSString *publicKeyID;

@property (nonatomic, strong) NSString *issuerPublicKeyID;

@property (nonatomic, strong) NSString *keyUsage;
@property (nonatomic, strong) NSString *extKeyUsages;
@property (nonatomic, strong) NSString *policies;

@property (nonatomic, strong) NSString *crlDistribPoint1;
@property (nonatomic, strong) NSString *crlDistribPoint2;

@property (nonatomic) BOOL isPowerCert;

@property (nonatomic) BOOL isSubjType;
@property (nonatomic) BOOL isSubjCA;

@property (nonatomic) NSInteger chainLength;

@property (nonatomic, strong) NSString *upn;

@property (nonatomic) EUPublicKeyType publicKeyType;
@property (nonatomic) EUKeyUsage keyUsageType;

@property (nonatomic, strong) NSString *rsaModul;
@property (nonatomic, strong) NSString *rsaExponent;

@property (nonatomic, strong) NSString *ocspAccessInfo;
@property (nonatomic, strong) NSString *issuerAccessInfo;
@property (nonatomic, strong) NSString *tspAccessInfo;

@property (nonatomic) BOOL isLimitValueAvailable;
@property (nonatomic) NSInteger limitValue;
@property (nonatomic, strong) NSString *limitValueCurrency;

@property (nonatomic) NSInteger subjType;
@property (nonatomic) NSInteger subjSubType;

@property (nonatomic, strong) NSString *subjUNZR;
@property (nonatomic, strong) NSString *subjCountry;
@property (nonatomic, strong) NSString *fingerprint;

@property (nonatomic) BOOL isQSCD;

@property (nonatomic, strong) NSString *subjUserID;
@end

@interface EUCertificate : NSObject
@property (nonatomic, strong) NSData *data;
@property (nonatomic, strong) EUCertificateInfoEx *infoEx;
@end

@interface EUTimeInfo : NSObject
@property (nonatomic) NSInteger version;
@property (nonatomic) BOOL isTimeAvail;
@property (nonatomic) BOOL isTimeStamp;
@property (nonatomic, strong) NSDate *time;
@property (nonatomic) BOOL isSignTimeStampAvail;
@property (nonatomic, strong) NSDate *signTimeStamp;
@end

@interface EUSCClientGate : NSObject
@property (nonatomic, strong) NSString *name;
@property (nonatomic, strong) NSString *connectPort;
@property (nonatomic, strong) NSString *address;
@property (nonatomic, strong) NSString *port;

@end

@interface EUSCClientStatistic : NSObject
@property (nonatomic, strong) NSNumber *activeSessions;
@property (nonatomic, strong) NSNumber *gatedSessions;
@property (nonatomic, strong) NSNumber *unprotectedData;
@property (nonatomic, strong) NSNumber *protectedData;

@end

@interface EUUserInfo : NSObject
@property (nonatomic) NSInteger version;

@property (nonatomic, strong) NSString *commonName;
@property (nonatomic, strong) NSString *locality;
@property (nonatomic, strong) NSString *state;
@property (nonatomic, strong) NSString *organization;
@property (nonatomic, strong) NSString *orgUnit;
@property (nonatomic, strong) NSString *title;
@property (nonatomic, strong) NSString *street;
@property (nonatomic, strong) NSString *phone;
@property (nonatomic, strong) NSString *surname;
@property (nonatomic, strong) NSString *givenname;
@property (nonatomic, strong) NSString *email;
@property (nonatomic, strong) NSString *dns;
@property (nonatomic, strong) NSString *edrpouCode;
@property (nonatomic, strong) NSString *drfoCode;
@property (nonatomic, strong) NSString *nbuCode;
@property (nonatomic, strong) NSString *spfmCode;
@property (nonatomic, strong) NSString *oCode;
@property (nonatomic, strong) NSString *ouCode;
@property (nonatomic, strong) NSString *userCode;
@property (nonatomic, strong) NSString *upn;
@property (nonatomic, strong) NSString *unzr;
@property (nonatomic, strong) NSString *country;
@end

@interface EURequestInfo: NSObject
@property (nonatomic, assign) EURequestType type;
@property (nonatomic, strong) NSData *data;
@property (nonatomic, strong) NSString *name;

@property (nonatomic) BOOL isFilled;

@property (nonatomic) NSInteger version;

@property (nonatomic) BOOL isSimple;

@property (nonatomic, strong) NSString *subject;
@property (nonatomic, strong) NSString *subjCN;
@property (nonatomic, strong) NSString *subjOrg;
@property (nonatomic, strong) NSString *subjOrgUnit;
@property (nonatomic, strong) NSString *subjTitle;
@property (nonatomic, strong) NSString *subjState;
@property (nonatomic, strong) NSString *subjLocality;
@property (nonatomic, strong) NSString *subjFullName;
@property (nonatomic, strong) NSString *subjAddress;
@property (nonatomic, strong) NSString *subjPhone;
@property (nonatomic, strong) NSString *subjEMail;
@property (nonatomic, strong) NSString *subjDNS;
@property (nonatomic, strong) NSString *subjEDRPOUCode;
@property (nonatomic, strong) NSString *subjDRFOCode;
@property (nonatomic, strong) NSString *subjNBUCode;
@property (nonatomic, strong) NSString *subjSPFMCode;
@property (nonatomic, strong) NSString *subjOCode;
@property (nonatomic, strong) NSString *subjOUCode;
@property (nonatomic, strong) NSString *subjUserCode;

@property (nonatomic) BOOL isCertTimes;
@property (nonatomic, strong) NSDate *certBeginTime;
@property (nonatomic, strong) NSDate *certEndTime;
@property (nonatomic) BOOL isPrivKeyTimes;
@property (nonatomic, strong) NSDate *privKeyBeginTime;
@property (nonatomic, strong) NSDate *privKeyEndTime;

@property (nonatomic) EUPublicKeyType publicKeyType;

@property (nonatomic) NSInteger publicKeyBits;
@property (nonatomic, strong) NSString *publicKey;
@property (nonatomic, strong) NSString *rsaModul;
@property (nonatomic, strong) NSString *rsaExponent;

@property (nonatomic, strong) NSString *publicKeyID;

@property (nonatomic, strong) NSString *extKeyUsages;

@property (nonatomic, strong) NSString *crlDistribPoint1;
@property (nonatomic, strong) NSString *crlDistribPoint2;

@property (nonatomic) BOOL isSubjType;
@property (nonatomic) NSInteger subjType;
@property (nonatomic) NSInteger subjSubType;

@property (nonatomic) BOOL isSelfSigned;
@property (nonatomic, strong) NSString *signIssuer;
@property (nonatomic, strong) NSString *signSerial;

@property (nonatomic, strong) NSString *subjUNZR;

@property (nonatomic, strong) NSString *subjCountry;

@property (nonatomic) BOOL isQSCD;
@end

@interface EUJKSPrivateKeyInfo : NSObject
@property (nonatomic, strong) NSString *alias;
@property (nonatomic, strong) NSData *privateKey;
@property (nonatomic, strong) NSArray<EUCertificate*> *certificates;
@end

@interface EUSessionContext : NSObject
@end

@interface EUContext: NSObject
@end

@interface EUHashContext: NSObject
@end

@interface EUPrivateKeyContext: NSObject
@end

@interface EUSignCPObjC : NSObject
+ (instancetype) shared;

- (BOOL) isInitialized;
- (BOOL) initialize:(NSData *) settings
       certificates:(NSData *) certificates
              error:(NSError **) error;
- (void) finalize;

- (NSArray<EUCASettings *>*) getCAs;

- (BOOL) setModeSettings:(BOOL) isOffline
				   error:(NSError **) error;

- (BOOL) protectData:(NSData *) data
		  byPassword:(NSString *) password
	   protectedData:(NSData *_Nullable *_Nullable) protectedData
			   error:(NSError **) error;
- (BOOL) unprotectData:(NSData *) protectedData
			byPassword:(NSString *) password
				  data:(NSData *_Nullable *_Nullable) data
				 error:(NSError **) error;

- (BOOL) parseCertificateEx:(NSData *) certificate
				 certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
					  error:(NSError **) error;
- (BOOL) saveCertificate:(NSData *) certificate
				   error:(NSError **) error;
- (BOOL) saveCertificates:(NSData *) certificates
					error:(NSError **) error;
- (BOOL) getCertificateChain:(NSData *) certificate
			  caCertificates:(NSArray<NSData *>* _Nullable * _Nullable) caCertificates
					   error:(NSError **) error;

- (BOOL) getTSP:(EUCtxHashAlgo) hashAlgo
		   hash:(NSData *) hash
   byAccessInfo:(NSString *) accessInfo
 accessInfoPort:(NSString *) accessInfoPort
			tsp:(NSData *_Nullable *_Nullable) tsp
		  error:(NSError **) error;
- (BOOL) getOCSPResponse:(NSData *) certificate
			byAccessInfo:(NSString *) accessInfo
		  accessInfoPort:(NSString *) accessInfoPort
			ocspResponse:(NSData *_Nullable *_Nullable) ocspResponse
				   error:(NSError **) error;

- (BOOL) getJKSPrivateKeys:(NSData *) privateKey
				   jksKeys:(NSArray<EUJKSPrivateKeyInfo *> *_Nullable*_Nullable) jksKeys
					 error:(NSError **) error;
- (BOOL) enumKeyMediaTypes:(NSArray<NSString *>*_Nullable*_Nullable) keyMediaTypes
					 error:(NSError **) error;
- (BOOL) enumKeyMediaDevicesForType:(NSInteger) keyMediaType
							devices:(NSArray<NSString *>* _Nullable * _Nullable) keyMediaDevices
							  error:(NSError **) error;

- (BOOL) isPrivateKeyExists:(NSInteger) typeIndex
				deviceIndex:(NSInteger) deviceIndex
				   password:(NSString *) password;
- (BOOL) destroyPrivateKey:(NSInteger) typeIndex
			   deviceIndex:(NSInteger) deviceIndex
				  password:(NSString *) password
					 error:(NSError **) error;
- (BOOL) generatePrivateKey:(NSInteger) typeIndex
				deviceIndex:(NSInteger) deviceIndex
				   password:(NSString *) password
		setKeyMediaPassword:(BOOL) isSetKeyMediaPassword
				 uaKeysType:(EUKeysType) uaKeysType
			   uaDSKeysSpec:(EUKeysLengthDSUA) uaDSKeysSpec
			  uaKEPKeysSpec:(EUKeysLengthKEPUA) uaKEPKeysSpec
				intKeysType:(EUKeysType) intKeysType
				rsaKeysSpec:(EUKeysLengthDSRSA) rsaKeysSpec
			  ecdsaKeysSpec:(EUKeysLengthDSECDSA) ecdsaKeysSpec
				   userInfo:(EUUserInfo * _Nullable) userInfo
			   extKeyUsages:(NSString * _Nullable) extKeyUsages
				   requests:(NSArray<EURequestInfo *>* _Nullable * _Nullable) requests
					  error:(NSError **) error;
- (BOOL) generatePrivateKeyBinary:(NSString *) password
					   uaKeysType:(EUKeysType) uaKeysType
					 uaDSKeysSpec:(EUKeysLengthDSUA) uaDSKeysSpec
					uaKEPKeysSpec:(EUKeysLengthKEPUA) uaKEPKeysSpec
					  intKeysType:(EUKeysType) intKeysType
					  rsaKeysSpec:(EUKeysLengthDSRSA) rsaKeysSpec
					ecdsaKeysSpec:(EUKeysLengthDSECDSA) ecdsaKeysSpec
						 userInfo:(EUUserInfo * _Nullable) userInfo
					 extKeyUsages:(NSString * _Nullable) extKeyUsages
					   privateKey:(NSData *_Nullable *_Nullable) privateKey
						 requests:(NSArray<EURequestInfo *> *_Nullable *_Nullable) requests
							error:(NSError **) error;

- (BOOL) isPrivateKeyReaded;
- (BOOL) readPrivateKey:(NSInteger) typeIndex
			deviceIndex:(NSInteger) deviceIndex
			   password:(NSString *) password
		   certificates:(NSArray<NSData *>* _Nullable) certificates
			 caIssuerCN:(NSString * _Nullable) caIssuerCN
				  error:(NSError **) error;
- (BOOL) readPrivateKeyBinary:(NSData *) privateKey
                     password:(NSString *) password
                 certificates:(NSArray<NSData *>* _Nullable) certificates
                   caIssuerCN:(NSString * _Nullable) caIssuerCN
                        error:(NSError **) error;
- (BOOL) getOwnCertificateWithPublicKeyType:(EUPublicKeyType) keyType
								   keyUsage:(EUKeyUsage) keyUsage
								certificate:(NSData *_Nullable *_Nullable) certificate
									  error:(NSError **) error;
- (void) resetPrivateKey;

- (void) ctxFreePrivateKey:(EUPrivateKeyContext *) pkContext;
- (BOOL) ctxReadPrivateKey:(EUContext *) context
				 typeIndex:(NSInteger) typeIndex
			   deviceIndex:(NSInteger) deviceIndex
				  password:(NSString *) password
			  certificates:(NSArray<NSData *>* _Nullable) certificates
				caIssuerCN:(NSString * _Nullable) caIssuerCN
		 privateKeyContext:(EUPrivateKeyContext *_Nullable *_Nullable) pkContext
					 error:(NSError **) error;
- (BOOL) ctxReadPrivateKeyBinary:(EUContext *) context
					  privateKey:(NSData *) privateKey
						password:(NSString *) password
					certificates:(NSArray<NSData *>* _Nullable) certificates
					  caIssuerCN:(NSString * _Nullable) caIssuerCN
			   privateKeyContext:(EUPrivateKeyContext *_Nullable *_Nullable) pkContext
						   error:(NSError **) error;
- (BOOL) ctxGetOwnCertificates:(EUPrivateKeyContext *) pkContext
				  certificates:(NSArray<EUCertificate *> *_Nullable *_Nullable) certificates
						 error:(NSError **) error;

- (BOOL) createEmptySign:(NSData *) data
					sign:(NSData *_Nullable *_Nullable) sign
				   error:(NSError **) error;
- (BOOL) createSignerBegin:(NSData *) certificate
					  hash:(NSData *) hash
					signer:(NSData *_Nullable *_Nullable) signer
				 attrsHash:(NSData *_Nullable *_Nullable) attrsHash
					 error:(NSError **) error;
- (BOOL) createRevocationInfoAttributes:(NSInteger) revocationReferences
						  ocspResponses:(NSArray<NSData *>*) ocspResponses
			   revocationReferencesAttr:(NSData *_Nullable *_Nullable) revocationReferencesAttr
				   revocationValuesAttr:(NSData *_Nullable *_Nullable) revocationValuesAttr
								  error:(NSError **) error;
- (BOOL) createCACertificateInfoAttributes:(NSArray<NSData *>*) caCertificates
				 certificateReferencesAttr:(NSData *_Nullable *_Nullable) certificateReferencesAttr
					 certificateValuesAttr:(NSData *_Nullable *_Nullable) certificateValuesAttr
									 error:(NSError **) error;
- (BOOL) appendSignerUnsignedAttribute:(NSData *) previousSigner
							   attrOID:(NSString *) attrOID
							 attrValue:(NSData *) attrValue
								signer:(NSData *_Nullable *_Nullable) signer
								 error:(NSError **) error;
- (BOOL) createSignerEnd:(NSData *) unsignedSigner
			   signarure:(NSData *) signarure
				  signer:(NSData *_Nullable *_Nullable) signer
				   error:(NSError **) error;
- (BOOL) getSigner:(NSData *) sign
		 signIndex:(NSInteger) signIndex
			signer:(NSData *_Nullable *_Nullable) signer
			 error:(NSError **) error;
- (BOOL) appendSigner:(NSData *) signer
		  certificate:(NSData *) certificate
		 previousSign:(NSData *) previousSign
				 sign:(NSData *_Nullable *_Nullable) sign
				error:(NSError **) error;
- (BOOL) getSignsCount:(NSData *) sign
			signsCount:(NSInteger *) signsCount
				 error:(NSError **) error;
- (BOOL) getSignerInfo:(NSData *) sign
			 signIndex:(NSInteger) signIndex
			certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
		   certificate:(NSData *_Nullable *_Nullable) certificate
				 error:(NSError **) error;
- (BOOL) getSignTimeInfo:(NSData *) sign
			   signIndex:(NSInteger) signIndex
				timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
				   error:(NSError **) error;
- (BOOL) signData:(NSData *) data
		 external:(BOOL) isExternal
		signature:(NSData *_Nullable *_Nullable) signature
			error:(NSError **) error;
- (BOOL) verifyData:(NSData *) data
		  signIndex:(NSInteger) signIndex
		  signature:(NSData *) signature
		   signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
			  error:(NSError **) error;
- (BOOL) verifyDataInternal:(NSInteger) signIndex
				  signature:(NSData *) signature
					   data:(NSData *_Nullable *_Nullable) data
				   signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
					  error:(NSError **) error;

- (void) sessionDestroy:(EUSessionContext *) session;
- (BOOL) sessionGetPeerCertificateInfo:(EUSessionContext *) session
							  signInfo:(EUCertificateInfo *_Nullable *_Nullable) certInfo
								 error:(NSError **) error;
- (BOOL) clientSessionCreateStep1:(NSUInteger) expireTime
						  session:(EUSessionContext *_Nullable *_Nullable) session
					   clientData:(NSData *_Nullable *_Nullable) clientData
							error:(NSError **) error;
- (BOOL) serverSessionCreateStep1:(NSUInteger) expireTime
					   clientData:(NSData *) clientData
						  session:(EUSessionContext *_Nullable *_Nullable) session
					   serverData:(NSData *_Nullable *_Nullable) serverData
							error:(NSError **) error;
- (BOOL) serverSessionCreateStep1:(NSUInteger) expireTime
						  encAlgo:(EUSessionEncAlgo) encAlgo
					   clientData:(NSData *) clientData
						  session:(EUSessionContext *_Nullable *_Nullable) session
					   serverData:(NSData *_Nullable *_Nullable) serverData
							error:(NSError **) error;
- (BOOL) clientSessionCreateStep2:(EUSessionContext *) session
					   serverData:(NSData *) serverData
					   clientData:(NSData *_Nullable *_Nullable) clientData
							error:(NSError **) error;
- (BOOL) serverSessionCreateStep2:(EUSessionContext *) session
					   clientData:(NSData *) clientData
							error:(NSError **) error;
- (BOOL) sessionEncrypt:(EUSessionContext *) session
				   data:(NSData *) data
		  encryptedData:(NSData *_Nullable *_Nullable) encryptedData
				  error:(NSError **) error;
- (BOOL) sessionDecrypt:(EUSessionContext *) session
		  encryptedData:(NSData *) encryptedData
				   data:(NSData *_Nullable *_Nullable) data
				  error:(NSError **) error;
- (BOOL) sessionEncryptContinue:(EUSessionContext *) session
						   data:(NSMutableData *) data
						  error:(NSError **) error;
- (BOOL) sessionDecryptContinue:(EUSessionContext *) session
						   data:(NSMutableData *) data
						  error:(NSError **) error;

- (BOOL) asicSignDataWithASiCType:(EUASiCType) asicType
						 signType:(EUASiCSignType) signType
						signLevel:(NSInteger) signLevel
					   references:(NSArray<EUDataReference *> *) references
						 asicData:(NSData *_Nullable *_Nullable) asicData
							error:(NSError **) error;
- (BOOL) asicVerifyData:(NSData *) asicData
			  signIndex:(NSInteger) signIndex
			   signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
				  error:(NSError **) error;
- (BOOL) asicGetASiCType:(NSData *) asicData
				asicType:(EUASiCType *) asicType
				   error:(NSError **) error;
- (BOOL) asicGetSignType:(NSData *) asicData
				signType:(EUASiCSignType *) signType
				   error:(NSError **) error;
- (BOOL) asicGetSignsCount:(NSData *) asicData
				signsCount:(NSInteger *) signsCount
					 error:(NSError **) error;
- (BOOL) asicGetSignerInfo:(NSData *) asicData
				 signIndex:(NSInteger) signIndex
				certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
			   certificate:(NSData *_Nullable *_Nullable) certificate
					 error:(NSError **) error;
- (BOOL) asicGetSignTimeInfo:(NSData *) asicData
				   signIndex:(NSInteger) signIndex
					timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
					   error:(NSError **) error;
- (BOOL) asicGetSignReferences:(NSData *) asicData
					 signIndex:(NSInteger) signIndex
			   referencesNames:(NSArray <NSString *> *_Nullable *_Nullable) referencesNames
						 error:(NSError **) error;
- (BOOL) asicGetReference:(NSString *) name
				 asicData:(NSData *) asicData
			referenceData:(NSData *_Nullable *_Nullable) referenceData
					error:(NSError **) error;

- (BOOL) xadesSignDataWithXAdESType:(EUXAdESType) xadesType
						  signLevel:(EUXAdESSignLevel) signLevel
						 references:(NSArray<EUDataReference *> *) references
						  xadesData:(NSData *_Nullable *_Nullable) xadesData
							  error:(NSError **) error;
- (BOOL) xadesVerifyData:(NSData *) xadesData
			   signIndex:(NSInteger) signIndex
			  references:(NSArray<EUDataReference *> *) references
				signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
				   error:(NSError **) error;
- (BOOL) xadesGetType:(NSData *) xadesData
			 signType:(EUXAdESType *) signType
				error:(NSError **) error;
- (BOOL) xadesGetSignsCount:(NSData *) xadesData
				 signsCount:(NSInteger *) signsCount
					  error:(NSError **) error;
- (BOOL) xadesGetSignerInfo:(NSData *) xadesData
				  signIndex:(NSInteger) signIndex
				 certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
				certificate:(NSData *_Nullable *_Nullable) certificate
					  error:(NSError **) error;
- (BOOL) xadesGetSignTimeInfo:(NSData *) xadesData
					signIndex:(NSInteger) signIndex
					 timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
						error:(NSError **) error;
- (BOOL) xadesGetSignReferences:(NSData *) xadesData
					  signIndex:(NSInteger) signIndex
				referencesNames:(NSArray <NSString *> *_Nullable *_Nullable) referencesNames
						  error:(NSError **) error;
- (BOOL) xadesGetReference:(NSString *) name
				 xadesData:(NSData *) xadesData
			 referenceData:(NSData *_Nullable *_Nullable) referenceData
					 error:(NSError **) error;

- (BOOL) pdfSignData:(NSData *) pdfData
		   signLevel:(EUPAdESSignLevel) signLevel
	   signedPDFData:(NSData *_Nullable *_Nullable) signedPDFData
			   error:(NSError **) error;
- (BOOL) pdfVerifyData:(NSData *) signedPDFData
			 signIndex:(NSInteger) signIndex
			  signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
				 error:(NSError **) error;
- (BOOL) pdfGetSignsCount:(NSData *) signedPDFData
			   signsCount:(NSInteger *) signsCount
					error:(NSError **) error;
- (BOOL) pdfGetSignerInfo:(NSData *) signedPDFData
				signIndex:(NSInteger) signIndex
			   certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
			  certificate:(NSData *_Nullable *_Nullable) certificate
					error:(NSError **) error;
- (BOOL) pdfGetSignTimeInfo:(NSData *) signedPDFData
				  signIndex:(NSInteger) signIndex
				   timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
					  error:(NSError **) error;

- (BOOL) envelopData:(NSData *) data
		toRecipients:(NSArray <NSData *>*) recipients
			signData:(BOOL) isSignData
	   envelopedData:(NSData *_Nullable *_Nullable) envelopedData
			   error:(NSError **) error;
- (BOOL) envelopData:(NSData *) data
		toRecipients:(NSArray <NSData *>*) recipients
  contentEncAlgoType:(EUContentEncAlgo) contentEncAlgo
			signData:(BOOL) isSignData
		  appendCert:(BOOL) isAppendCert
	   envelopedData:(NSData *_Nullable *_Nullable) envelopedData
			   error:(NSError **) error;
- (BOOL) developData:(NSData *) envelopedData
				data:(NSData *_Nullable *_Nullable) data
			senderInfo:(EUSignInfo *_Nullable *_Nullable) senderInfo
			   error:(NSError **) error;

- (BOOL) scClientIsRunning;
- (BOOL) scClientStart:(NSError **) error;
- (void) scClientStop;
- (BOOL) scClientAddGate:(EUSCClientGate *) gate
                   error:(NSError **) error;
- (BOOL) scClientRemoveGate:(EUSCClientGate *) gate
                      error:(NSError **) error;
- (BOOL) scClientGetStatistic:(EUSCClientStatistic *_Nullable *_Nullable) statistic
						error:(NSError **) error;

- (void) ctxFree:(EUContext *) context;
- (BOOL) ctxCreate:(EUContext *_Nullable *_Nullable) context
		     error:(NSError **) error;
- (BOOL) ctxSetParameter:(EUContext *) context
					name:(NSString *) name
				   value:(NSNumber *) value
				   error:(NSError **) error;

- (void) ctxFreeHash:(EUHashContext *) hashContext;
- (BOOL) ctxHashData:(EUContext *) context
			hashAlgo:(EUCtxHashAlgo) hashAlgo
		 certificate:(NSData *_Nullable) certificate
			    data:(NSData *) data
			    hash:(NSData *_Nullable *_Nullable) hash
		       error:(NSError **) error;
- (BOOL) ctxHashDataBegin:(EUContext *) context
				 hashAlgo:(EUCtxHashAlgo) hashAlgo
			  certificate:(NSData *_Nullable) certificate
			  hashContext:(EUHashContext *_Nullable *_Nullable) hashContext
					error:(NSError **) error;
- (BOOL) ctxHashDataContinue:(EUHashContext *) hashContext
						data:(NSData *) data
					   error:(NSError **) error;
- (BOOL) ctxHashDataEnd:(EUHashContext *) hashContext
				   hash:(NSData *_Nullable *_Nullable) hash
				  error:(NSError **) error;

- (BOOL) ctxSignData:(EUPrivateKeyContext *) pkContext
		    signAlgo:(EUCtxSignAlgo) signAlgo
				data:(NSData *) data
			external:(BOOL) isExternal
		  appendCert:(BOOL) isAppendCert
		   signature:(NSData *_Nullable *_Nullable) signature
			   error:(NSError **) error;
- (BOOL) ctxGetSignValue:(EUPrivateKeyContext *) pkContext
				signAlgo:(EUCtxSignAlgo) signAlgo
					hash:(NSData *) hash
			   signValue:(NSData *_Nullable *_Nullable) signValue
				   error:(NSError **) error;

@end

NS_ASSUME_NONNULL_END
