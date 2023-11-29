//================================================================================

#import "EUSignCPObjC.h"
#include <EUSignCP.h>

//================================================================================

#define DECLARE_CONTEXT_CLASS(Name)                 \
@interface Name()                                   \
    @property (nonatomic, assign) void* handle;     \
    + (instancetype) context:(void*) handle;        \
@end                                                \
@implementation Name                                \
+ (instancetype) context:(void*) handle             \
{                                                   \
    Name* context = [[Name alloc] init];            \
    context.handle = handle;                        \
    return context;                                 \
}                                                   \
@end

#define MAX_PATH 256

//================================================================================

const NSErrorDomain kEUSignCPErrorDomain = @"EUSignCPErrorDomain";

//================================================================================

@implementation EUDataReference : NSObject
+ (instancetype) reference:(NSString *) name
					  data:(NSData *) data
{
	EUDataReference *reference = [[EUDataReference alloc] init];
		
	reference.name = name;
	reference.data = data;
	
	return reference;
}
@end

//================================================================================

@implementation EUCASettings
+ (instancetype) settings:(NSDictionary *) settings
{
    EUCASettings *ca = [[EUCASettings alloc] init];
        
    ca.issuerCNs = [settings objectForKey:@"issuerCNs"];
    ca.address = [settings objectForKey:@"address"];
    ca.ocspAccessPointAddress = [settings objectForKey:@"ocspAccessPointAddress"];
    ca.ocspAccessPointPort = [settings objectForKey:@"ocspAccessPointPort"];
    ca.cmpAddress = [settings objectForKey:@"cmpAddress"];
    ca.tspAddress = [settings objectForKey:@"tspAddress"];
    ca.tspAddressPort = [settings objectForKey:@"tspAddressPort"];
    ca.certsInKey = [[settings objectForKey:@"certsInKey"] boolValue];

    return ca;
}
@end

//================================================================================

@implementation EUSignInfo : NSObject
@end

//================================================================================

@implementation EUCertificateInfo : NSObject
@end

//================================================================================

@implementation EUCertificateInfoEx : NSObject
@end

//================================================================================

@implementation EUCertificate : NSObject
@end

//================================================================================

@implementation EUTimeInfo : NSObject
@end

//================================================================================

@implementation EUSCClientGate : NSObject
@end

//================================================================================

@implementation EUSCClientStatistic : NSObject
@end

//================================================================================

@implementation EUUserInfo : NSObject
@end

//================================================================================

@implementation EURequestInfo : NSObject
@end

//================================================================================

@implementation EUJKSPrivateKeyInfo: NSObject
@end

//================================================================================

DECLARE_CONTEXT_CLASS(EUContext)
DECLARE_CONTEXT_CLASS(EUHashContext)
DECLARE_CONTEXT_CLASS(EUPrivateKeyContext)
DECLARE_CONTEXT_CLASS(EUSessionContext)

//================================================================================

typedef void* PVOID;
typedef unsigned long DWORD;
typedef unsigned long* PDWORD;
typedef unsigned char BYTE;
typedef unsigned char* PBYTE;

//================================================================================

@implementation NSString(Ext)

+ (NSString *) stringWithCP1251String:(char *) pszStr
{
    return [NSString
            stringWithCString:pszStr
            encoding:NSWindowsCP1251StringEncoding];
}

- (BOOL) getCP1251CString:(char *) buffer
                maxLength:(NSUInteger) maxBufferCount;
{
    memset(buffer, 0, maxBufferCount);
    
    return [self getCString:buffer
                  maxLength:maxBufferCount
                   encoding:NSWindowsCP1251StringEncoding];
}
@end

//================================================================================

@interface EUSignCPObjC ()
@property (nonatomic) DWORD dwLangCode;
@property (nonatomic, strong) NSArray<EUCASettings*>* CAs;
@end

//================================================================================

@implementation EUSignCPObjC
+ (instancetype) shared
{
    static EUSignCPObjC *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[self alloc] init];
    });
    return shared;
}

- (NSError *) makeError:(NSUInteger) error
{
    NSString *errorMessage = [NSString
        stringWithCString:EUGetErrorLangDesc(error, self.dwLangCode)
                 encoding:NSWindowsCP1251StringEncoding];
    
    NSDictionary *userInfo = [NSDictionary
        dictionaryWithObjectsAndKeys:errorMessage,
        NSLocalizedDescriptionKey, nil];

    return [[NSError alloc] initWithDomain:kEUSignCPErrorDomain
                                      code:error
                                  userInfo:userInfo];
}

- (id) init
{
    self = [super init];
    if (!self)
        return nil;
    
    NSString *lang = [[NSLocale preferredLanguages] firstObject];
    if ([lang hasPrefix:@"uk"])
        self.dwLangCode = EU_UA_LANG;
    else if ([lang hasPrefix:@"en"])
        self.dwLangCode = EU_EN_LANG;
    else if ([lang hasPrefix:@"ru"])
        self.dwLangCode = EU_RU_LANG;
    else
        self.dwLangCode = EU_DEFAULT_LANG;
    
    return self;
}

- (BOOL) setCAsAsData:(NSData *) data
{
    if (data == nil)
        return NO;
    
    self.CAs = nil;

    NSArray *settings = [NSJSONSerialization
        JSONObjectWithData:data options:0 error:nil];
    if (![settings isKindOfClass:[NSArray class]])
        return NO;
    
    NSMutableArray *CAs = [NSMutableArray array];
    for (NSDictionary *caData in settings)
    {
        EUCASettings *ca = [EUCASettings settings:caData];
        if (ca == nil)
            return NO;
        [CAs addObject:ca];
    }

    self.CAs = [NSArray arrayWithArray:CAs];
    
    return YES;
}

- (NSUInteger) setSettings:(NSData *) settingsData
              certificates:(NSData *) certificates
{
    EUCASettings*   ca = nil;
    int             bOnline;
    int             nValue;
    const char*     pszTSPAddress = "";
    const char*     pszTSPPort = "80";
    const char*     pszIssuerCN;
    const char*     pszAddress;
    const char*     pszPort;
    DWORD           dwError;
    
    if (![self setCAsAsData:settingsData])
        return EU_ERROR_BAD_PARAMETER;
   
    bOnline = self.CAs.count > 0 ? TRUE : FALSE;
    if (bOnline)
    {
        ca = [self.CAs objectAtIndex:0];
        pszTSPAddress = [ca.tspAddress cStringUsingEncoding:
            NSWindowsCP1251StringEncoding];
        pszTSPPort = [ca.tspAddressPort cStringUsingEncoding:
            NSWindowsCP1251StringEncoding];
    }
    
    nValue = EU_SETTINGS_ID_NONE;
    dwError = EUSetRuntimeParameter(
        (char *) EU_SAVE_SETTINGS_PARAMETER, &nValue,
        EU_SAVE_SETTINGS_PARAMETER_LENGTH);
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    dwError = EUSetModeSettings(!bOnline);
    if (dwError != EU_ERROR_NONE)
        return dwError;

    dwError = EUSetFileStoreSettings((char *) "",
        FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, 3600);
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    dwError = EUSetProxySettings(
        FALSE, FALSE, (char *)"", (char *)"",
        (char *)"", (char *)"", FALSE);
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    dwError = EUSetTSPSettings(
        bOnline, (char *) pszTSPAddress, (char *) pszTSPPort);
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    dwError = EUSetOCSPSettings(
        bOnline, TRUE, (char *) "czo.gov.ua", (char *)"80");
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    dwError = EUSetLDAPSettings(
        FALSE, (char *)"", (char *)"", TRUE,
        (char *)"", (char *)"");
    if (dwError != EU_ERROR_NONE)
        return dwError;
   
    dwError = EUSetCMPSettings(
        FALSE, (char *)"", (char *)"", (char *)"");
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    dwError = EUSetOCSPAccessInfoModeSettings(TRUE);
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    for (EUCASettings *ca in self.CAs)
    {
        if (!ca.ocspAccessPointAddress ||
            [ca.ocspAccessPointAddress isEqualToString:@""] ||
            !ca.ocspAccessPointPort ||
            [ca.ocspAccessPointPort isEqualToString:@""])
        {
            continue;
        }
                
        pszAddress = [ca.ocspAccessPointAddress
            cStringUsingEncoding:NSWindowsCP1251StringEncoding];
        pszPort = [ca.ocspAccessPointPort
            cStringUsingEncoding:NSWindowsCP1251StringEncoding];
        
        for (NSString *issuerCN in ca.issuerCNs)
        {
            pszIssuerCN = [issuerCN
                cStringUsingEncoding:NSWindowsCP1251StringEncoding];
            
            if (!pszIssuerCN || !pszAddress || !pszPort)
                return EU_ERROR_BAD_PARAMETER;
            
            dwError = EUSetOCSPAccessInfoSettings(
                (char *) pszIssuerCN,
                (char *) pszAddress, (char *) pszPort);
            if (dwError != EU_ERROR_NONE)
                return dwError;
        }
    }
    
    if (certificates == nil)
        return EU_ERROR_BAD_PARAMETER;
    
    dwError = EUSaveCertificates(
        (PBYTE) certificates.bytes, (DWORD) certificates.length);
    if (dwError != EU_ERROR_NONE)
        return dwError;
    
    return EU_ERROR_NONE;
}

- (NSDate *) dateFromLocalTime:(SYSTEMTIME *) pTime
{
	NSDateComponents *dateComponents =
	[[NSDateComponents alloc] init];
	
	[dateComponents setYear:pTime->wYear];
	[dateComponents setMonth:pTime->wMonth];
	[dateComponents setDay:pTime->wDay];
	[dateComponents setHour:pTime->wHour];
	[dateComponents setMinute:pTime->wMinute];
	[dateComponents setSecond:pTime->wSecond];
	[dateComponents setTimeZone:[NSTimeZone timeZoneWithName:@"Europe/Kiev"]];
	
	NSCalendar *calendar = [[NSCalendar alloc]
		initWithCalendarIdentifier:NSCalendarIdentifierGregorian];
	NSDate *date = [calendar dateFromComponents:dateComponents];
	
	return date;
}

- (EUSignInfo *) makeSignInfo:(EU_SIGN_INFO *) pSignInfo
{
	EUSignInfo *signInfo = [[EUSignInfo alloc] init];
	
	signInfo.isFilled = pSignInfo->bFilled ? YES : NO;
	
	signInfo.issuer = [NSString stringWithCP1251String:pSignInfo->pszIssuer];
	signInfo.issuerCN = [NSString stringWithCP1251String:pSignInfo->pszIssuerCN];
	signInfo.serial = [NSString stringWithCP1251String:pSignInfo->pszSerial];
	
	signInfo.subject = [NSString stringWithCP1251String:pSignInfo->pszSubject];
	signInfo.subjCN = [NSString stringWithCP1251String:pSignInfo->pszSubjCN];
	signInfo.subjOrg = [NSString stringWithCP1251String:pSignInfo->pszSubjOrg];
	signInfo.subjOrgUnit = [NSString stringWithCP1251String:pSignInfo->pszSubjOrgUnit];
	signInfo.subjTitle = [NSString stringWithCP1251String:pSignInfo->pszSubjTitle];
	signInfo.subjState = [NSString stringWithCP1251String:pSignInfo->pszSubjState];
	signInfo.subjLocality = [NSString stringWithCP1251String:pSignInfo->pszSubjLocality];
	signInfo.subjFullName = [NSString stringWithCP1251String:pSignInfo->pszSubjFullName];
	signInfo.subjAddress = [NSString stringWithCP1251String:pSignInfo->pszSubjAddress];
	signInfo.subjPhone = [NSString stringWithCP1251String:pSignInfo->pszSubjPhone];
	signInfo.subjEMail = [NSString stringWithCP1251String:pSignInfo->pszSubjEMail];
	signInfo.subjDNS = [NSString stringWithCP1251String:pSignInfo->pszSubjDNS];
	signInfo.subjEDRPOUCode = [NSString stringWithCP1251String:pSignInfo->pszSubjEDRPOUCode];
	signInfo.subjDRFOCode = [NSString stringWithCP1251String:pSignInfo->pszSubjDRFOCode];
	
	signInfo.isTimeAvail = pSignInfo->bTimeAvail ? YES : NO;
	signInfo.isTimeStamp = pSignInfo->bTimeStamp ? YES : NO;
	signInfo.time = [self dateFromLocalTime:&pSignInfo->Time];
	
	return signInfo;
}

- (EUCertificateInfo *) makeCertificateInfo:(EU_CERT_INFO *) pInfo
{
	EUCertificateInfo *info = [[EUCertificateInfo alloc] init];
	
	info.isFilled = pInfo->bFilled ? YES : NO;
	
	info.version = pInfo->dwVersion;
	
	info.issuer = [NSString stringWithCP1251String:pInfo->pszIssuer];
	info.issuerCN = [NSString stringWithCP1251String:pInfo->pszIssuerCN];
	info.serial = [NSString stringWithCP1251String:pInfo->pszSerial];
	
	info.subject = [NSString stringWithCP1251String:pInfo->pszSubject];
	info.subjCN = [NSString stringWithCP1251String:pInfo->pszSubjCN];
	info.subjOrg = [NSString stringWithCP1251String:pInfo->pszSubjOrg];
	info.subjOrgUnit = [NSString stringWithCP1251String:pInfo->pszSubjOrgUnit];
	info.subjTitle = [NSString stringWithCP1251String:pInfo->pszSubjTitle];
	info.subjState = [NSString stringWithCP1251String:pInfo->pszSubjState];
	info.subjLocality = [NSString stringWithCP1251String:pInfo->pszSubjLocality];
	info.subjFullName = [NSString stringWithCP1251String:pInfo->pszSubjFullName];
	info.subjAddress = [NSString stringWithCP1251String:pInfo->pszSubjAddress];
	info.subjPhone = [NSString stringWithCP1251String:pInfo->pszSubjPhone];
	info.subjEMail = [NSString stringWithCP1251String:pInfo->pszSubjEMail];
	info.subjDNS = [NSString stringWithCP1251String:pInfo->pszSubjDNS];
	info.subjEDRPOUCode = [NSString stringWithCP1251String:pInfo->pszSubjEDRPOUCode];
	info.subjDRFOCode = [NSString stringWithCP1251String:pInfo->pszSubjDRFOCode];
	
	info.subjNBUCode = [NSString stringWithCP1251String:pInfo->pszSubjNBUCode];
	info.subjSPFMCode = [NSString stringWithCP1251String:pInfo->pszSubjSPFMCode];
	info.subjOCode = [NSString stringWithCP1251String:pInfo->pszSubjOCode];
	info.subjOUCode = [NSString stringWithCP1251String:pInfo->pszSubjOUCode];
	info.subjUserCode = [NSString stringWithCP1251String:pInfo->pszSubjUserCode];
	
	info.certBeginTime = [self dateFromLocalTime:&pInfo->stCertBeginTime];
	info.certEndTime = [self dateFromLocalTime:&pInfo->stCertEndTime];
	info.isPrivKeyTimes = pInfo->bPrivKeyTimes ? YES : NO;
	info.privKeyBeginTime = [self dateFromLocalTime:&pInfo->stPrivKeyBeginTime];
	info.privKeyEndTime = [self dateFromLocalTime:&pInfo->stPrivKeyEndTime];
	
	info.publicKeyBits = pInfo->dwPublicKeyBits;
	info.publicKey = [NSString stringWithCP1251String:pInfo->pszPublicKey];
	info.publicKeyID = [NSString stringWithCP1251String:pInfo->pszPublicKeyID];
	
	info.isECDHPublicKey = pInfo->bECDHPublicKey ? YES : NO;
	info.ecdhPublicKeyBits = pInfo->dwECDHPublicKeyBits;
	info.ecdhPublicKey = [NSString stringWithCP1251String:pInfo->pszECDHPublicKey];
	info.ecdhPublicKeyID = [NSString stringWithCP1251String:pInfo->pszECDHPublicKeyID];
	
	info.issuerPublicKeyID = [NSString stringWithCP1251String:pInfo->pszIssuerPublicKeyID];
	
	info.keyUsage = [NSString stringWithCP1251String:pInfo->pszKeyUsage];
	info.extKeyUsages = [NSString stringWithCP1251String:pInfo->pszExtKeyUsages];
	info.policies = [NSString stringWithCP1251String:pInfo->pszPolicies];
	
	info.crlDistribPoint1 = [NSString stringWithCP1251String:pInfo->pszCRLDistribPoint1];
	info.crlDistribPoint2 = [NSString stringWithCP1251String:pInfo->pszCRLDistribPoint2];
	
	info.isPowerCert = pInfo->bPowerCert ? YES : NO;
	
	info.isSubjType = pInfo->bSubjType ? YES : NO;
	info.isSubjCA = pInfo->bSubjCA ? YES : NO;

	return info;
}

- (EUCertificateInfoEx *) makeCertificateInfoEx:(EU_CERT_INFO_EX *) pInfoEx
{
	EUCertificateInfoEx *infoEx = [[EUCertificateInfoEx alloc] init];
	
	infoEx.isFilled = pInfoEx->bFilled ? YES : NO;
	
	infoEx.version = pInfoEx->dwVersion;
	
	infoEx.issuer = [NSString stringWithCP1251String:pInfoEx->pszIssuer];
	infoEx.issuerCN = [NSString stringWithCP1251String:pInfoEx->pszIssuerCN];
	infoEx.serial = [NSString stringWithCP1251String:pInfoEx->pszSerial];
	
	infoEx.subject = [NSString stringWithCP1251String:pInfoEx->pszSubject];
	infoEx.subjCN = [NSString stringWithCP1251String:pInfoEx->pszSubjCN];
	infoEx.subjOrg = [NSString stringWithCP1251String:pInfoEx->pszSubjOrg];
	infoEx.subjOrgUnit = [NSString stringWithCP1251String:pInfoEx->pszSubjOrgUnit];
	infoEx.subjTitle = [NSString stringWithCP1251String:pInfoEx->pszSubjTitle];
	infoEx.subjState = [NSString stringWithCP1251String:pInfoEx->pszSubjState];
	infoEx.subjLocality = [NSString stringWithCP1251String:pInfoEx->pszSubjLocality];
	infoEx.subjFullName = [NSString stringWithCP1251String:pInfoEx->pszSubjFullName];
	infoEx.subjAddress = [NSString stringWithCP1251String:pInfoEx->pszSubjAddress];
	infoEx.subjPhone = [NSString stringWithCP1251String:pInfoEx->pszSubjPhone];
	infoEx.subjEMail = [NSString stringWithCP1251String:pInfoEx->pszSubjEMail];
	infoEx.subjDNS = [NSString stringWithCP1251String:pInfoEx->pszSubjDNS];
	infoEx.subjEDRPOUCode = [NSString stringWithCP1251String:pInfoEx->pszSubjEDRPOUCode];
	infoEx.subjDRFOCode = [NSString stringWithCP1251String:pInfoEx->pszSubjDRFOCode];
	
	infoEx.subjNBUCode = [NSString stringWithCP1251String:pInfoEx->pszSubjNBUCode];
	infoEx.subjSPFMCode = [NSString stringWithCP1251String:pInfoEx->pszSubjSPFMCode];
	infoEx.subjOCode = [NSString stringWithCP1251String:pInfoEx->pszSubjOCode];
	infoEx.subjOUCode = [NSString stringWithCP1251String:pInfoEx->pszSubjOUCode];
	infoEx.subjUserCode = [NSString stringWithCP1251String:pInfoEx->pszSubjUserCode];
	
	infoEx.certBeginTime = [self dateFromLocalTime:&pInfoEx->stCertBeginTime];
	infoEx.certEndTime = [self dateFromLocalTime:&pInfoEx->stCertEndTime];
	infoEx.isPrivKeyTimes = pInfoEx->bPrivKeyTimes ? YES : NO;
	infoEx.privKeyBeginTime = [self dateFromLocalTime:&pInfoEx->stPrivKeyBeginTime];
	infoEx.privKeyEndTime = [self dateFromLocalTime:&pInfoEx->stPrivKeyEndTime];
	
	infoEx.publicKeyBits = pInfoEx->dwPublicKeyBits;
	infoEx.publicKey = [NSString stringWithCP1251String:pInfoEx->pszPublicKey];
	infoEx.publicKeyID = [NSString stringWithCP1251String:pInfoEx->pszPublicKeyID];
	
	infoEx.issuerPublicKeyID = [NSString stringWithCP1251String:pInfoEx->pszIssuerPublicKeyID];
	
	infoEx.keyUsage = [NSString stringWithCP1251String:pInfoEx->pszKeyUsage];
	infoEx.extKeyUsages = [NSString stringWithCP1251String:pInfoEx->pszExtKeyUsages];
	infoEx.policies = [NSString stringWithCP1251String:pInfoEx->pszPolicies];
	
	infoEx.crlDistribPoint1 = [NSString stringWithCP1251String:pInfoEx->pszCRLDistribPoint1];
	infoEx.crlDistribPoint2 = [NSString stringWithCP1251String:pInfoEx->pszCRLDistribPoint2];
	
	infoEx.isPowerCert = pInfoEx->bPowerCert ? YES : NO;
	
	infoEx.isSubjType = pInfoEx->bSubjType ? YES : NO;
	infoEx.isSubjCA = pInfoEx->bSubjCA ? YES : NO;
	
	infoEx.chainLength = pInfoEx->iChainLength;
	
	infoEx.upn = [NSString stringWithCP1251String:pInfoEx->pszUPN];
	
	infoEx.publicKeyType = (EUPublicKeyType) pInfoEx->dwPublicKeyType;
	infoEx.keyUsageType = (EUKeyUsage) pInfoEx->dwKeyUsage;

	infoEx.rsaModul = [NSString stringWithCP1251String:pInfoEx->pszRSAModul];
	infoEx.rsaExponent = [NSString stringWithCP1251String:pInfoEx->pszRSAExponent];
	
	infoEx.ocspAccessInfo = [NSString stringWithCP1251String:pInfoEx->pszOCSPAccessInfo];
	infoEx.issuerAccessInfo = [NSString stringWithCP1251String:pInfoEx->pszIssuerAccessInfo];
	infoEx.tspAccessInfo = [NSString stringWithCP1251String:pInfoEx->pszTSPAccessInfo];
	
	infoEx.isLimitValueAvailable = pInfoEx->bLimitValueAvailable ? YES : NO;
	infoEx.limitValue = pInfoEx->dwLimitValue;
	infoEx.limitValueCurrency = [NSString stringWithCP1251String:pInfoEx->pszLimitValueCurrency];
	
	infoEx.subjType = pInfoEx->dwSubjType;
	infoEx.subjSubType = pInfoEx->dwSubjSubType;
	
	infoEx.subjUNZR = [NSString stringWithCP1251String:pInfoEx->pszSubjUNZR];
	infoEx.subjCountry = [NSString stringWithCP1251String:pInfoEx->pszSubjCountry];
	infoEx.fingerprint = [NSString stringWithCP1251String:pInfoEx->pszFingerprint];
	
	infoEx.isQSCD = pInfoEx->bQSCD ? YES : NO;
	
	infoEx.subjUserID = [NSString stringWithCP1251String:pInfoEx->pszSubjUserID];
	
	return infoEx;
}

- (EUCertificate *) makeCertificate:(PBYTE) pbCertificate
				  certificateLength:(DWORD) dwCertificateLength
							 infoEx:(PEU_CERT_INFO_EX) pInfoEx
{
	EUCertificate *certificate = [[EUCertificate alloc] init];
	certificate.data = [NSData dataWithBytes:pbCertificate length:dwCertificateLength];
	certificate.infoEx = [self makeCertificateInfoEx:pInfoEx];
	return certificate;
}

- (EUTimeInfo *) makeTimeInfo:(PEU_TIME_INFO) pTimeInfo
{
	EUTimeInfo *info = [[EUTimeInfo alloc] init];
	info.version = pTimeInfo->dwVersion;
	info.isTimeAvail = pTimeInfo->bTimeAvail ? YES : NO;
	info.isTimeStamp = pTimeInfo->bTimeStamp ? YES : NO;
	info.time = [self dateFromLocalTime:&pTimeInfo->Time];
	info.isSignTimeStampAvail = pTimeInfo->bSignTimeStampAvail ? YES : NO;
	info.signTimeStamp = [self dateFromLocalTime:&pTimeInfo->SignTimeStamp];
	return info;
}

- (BOOL) getReferences:(NSArray<EUDataReference *> *) references
	   referencesNames:(char **) ppszReferencesNames
		referencesData:(PBYTE **) pppbReferencesData
  referencesDataLength:(DWORD **) ppdwReferencesLength
{
	char *pszReferencesNames = NULL;
	NSInteger referencesNamesSize;
	const char *pszTmp;
	char *pszTmp2;
	PBYTE *ppbReferencesData = NULL;
	DWORD *pdwReferencesLength = NULL;
	NSInteger referencesCount;
	
	*ppszReferencesNames = NULL;
	*pppbReferencesData = NULL;
	*ppdwReferencesLength = NULL;
	
	referencesCount = [references count];
	
	if (referencesCount < 1)
		return NO;
	
	referencesNamesSize = 0;
	for (NSInteger i = 0; i < referencesCount; i++)
	{
		pszTmp = [[references objectAtIndex:i].name cStringUsingEncoding:NSWindowsCP1251StringEncoding];
		referencesNamesSize += strlen(pszTmp) + 1;
	}
	referencesNamesSize += 1;
	
	pszReferencesNames = new char[referencesNamesSize];
	ppbReferencesData = new PBYTE[referencesCount];
	pdwReferencesLength = new DWORD[referencesCount];
	if (pszReferencesNames == NULL ||
		ppbReferencesData == NULL ||
		pdwReferencesLength == NULL)
	{
		[self freeReferencesNames:pszReferencesNames referencesData:ppbReferencesData referencesDataLength:pdwReferencesLength];
		return NO;
	}
	
	pszTmp2 = pszReferencesNames;
	for (NSInteger i = 0; i < referencesCount; i++)
	{
		pszTmp = [[references objectAtIndex:i].name cStringUsingEncoding:NSWindowsCP1251StringEncoding];
		strcpy(pszTmp2, pszTmp);
		pszTmp2 += strlen(pszTmp) + 1;
		
		ppbReferencesData[i] = (PBYTE) [references objectAtIndex:i].data.bytes;
		pdwReferencesLength[i] = [references objectAtIndex:i].data.length;
	}
	*pszTmp2 = '\0';
	
	*ppszReferencesNames = pszReferencesNames;
	*pppbReferencesData = ppbReferencesData;
	*ppdwReferencesLength = pdwReferencesLength;
	
	return YES;
}

- (void) freeReferencesNames:(char *) pszReferencesNames
			  referencesData:(PBYTE *) ppbReferencesData
		referencesDataLength:(DWORD *) pdwReferencesLength
{
	if (pszReferencesNames != NULL)
		delete[] pszReferencesNames;
	if (ppbReferencesData != NULL)
		delete[] ppbReferencesData;
	if (pdwReferencesLength != NULL)
		delete[] pdwReferencesLength;
}

- (NSArray <NSString *> *) makeStringsArray:(char *) pszStr
{
	NSMutableArray *array = [[NSMutableArray alloc] init];
	
	while (*pszStr != '\0')
	{
		[array addObject:[NSString stringWithCP1251String:pszStr]];
		pszStr += strlen(pszStr) + 1;
	}
	
	return [NSArray arrayWithArray:array];
}

- (NSArray<NSData*> *) makeArrayOfByteArrays:(DWORD) dwCount
									  arrays:(PBYTE *) ppbArrays
							  arraysLengthes:(PDWORD) pdwArraysLengthes
{
	NSMutableArray<NSData *> *array = [NSMutableArray array];

	for (DWORD dwI = 0; dwI < dwCount; dwI++)
	{
		[array addObject:[NSData dataWithBytes:ppbArrays[dwI] 
										length:pdwArraysLengthes[dwI]]];
	}

	return [NSArray arrayWithArray:array];
}

- (BOOL) getArrayOfByteArrays:(NSArray<NSData*> *) array
						count:(PDWORD) pdwCount
					   arrays:(PBYTE **) pppbArrays
			   arraysLengthes:(PDWORD *) ppdwArraysLengthes
{
	DWORD			dwCount;
	PBYTE			*ppbArrays;
	PDWORD			pdwArraysLengthes;

	dwCount = [array count];

	ppbArrays = new PBYTE[dwCount];
	if (ppbArrays == NULL)
		return NO;

	pdwArraysLengthes = new DWORD[dwCount];
	if (pdwArraysLengthes == NULL)
	{
		delete[] ppbArrays;

		return NO;
	}

	for (DWORD dwI = 0; dwI < dwCount; dwI++)
	{
		ppbArrays[dwI] = (PBYTE) [array objectAtIndex:dwI].bytes;
		pdwArraysLengthes[dwI] = [array objectAtIndex:dwI].length;
	}

	if (pdwCount)
		*pdwCount = dwCount;

	if (pppbArrays)
		*pppbArrays = ppbArrays;
	else
		delete[] ppbArrays;

	if (ppdwArraysLengthes)
		*ppdwArraysLengthes = pdwArraysLengthes;
	else
		delete[] pdwArraysLengthes;

	return YES;
}

- (void) freeArrayOfByteArrays:(DWORD) dwCount
						arrays:(PBYTE *) ppbArrays
				arraysLengthes:(PDWORD) pdwArraysLengthes
{
	if (ppbArrays != NULL)
		delete[] ppbArrays;
	if (pdwArraysLengthes != NULL)
		delete[] pdwArraysLengthes;
}

- (BOOL) makeUserInfo:(EUUserInfo *) userInfo
			cUserInfo:(EU_USER_INFO *) pUserInfo
{
	if (userInfo == nil)
		return NO;
	
	memset(pUserInfo, 0, sizeof(EU_USER_INFO));
	
	pUserInfo->dwVersion = EU_USER_INFO_VERSION;
	
	if (![userInfo.commonName
		  getCP1251CString:pUserInfo->szCommonName
				 maxLength:EU_COMMON_NAME_MAX_LENGTH] ||
		![userInfo.locality
		  getCP1251CString:pUserInfo->szLocality
				 maxLength:EU_LOCALITY_MAX_LENGTH] ||
		![userInfo.state
		  getCP1251CString:pUserInfo->szState
			     maxLength:EU_STATE_MAX_LENGTH] ||
		![userInfo.organization
		  getCP1251CString:pUserInfo->szOrganiztion
			     maxLength:EU_ORGANIZATION_MAX_LENGTH] ||
		![userInfo.orgUnit
		  getCP1251CString:pUserInfo->szOrgUnit
			     maxLength:EU_ORG_UNIT_MAX_LENGTH] ||
		![userInfo.title
		  getCP1251CString:pUserInfo->szTitle
			     maxLength:EU_TITLE_MAX_LENGTH] ||
		![userInfo.street
		  getCP1251CString:pUserInfo->szStreet
				 maxLength:EU_STREET_MAX_LENGTH] ||
		![userInfo.phone
		  getCP1251CString:pUserInfo->szPhone
			     maxLength:EU_PHONE_MAX_LENGTH] ||
		![userInfo.surname
		  getCP1251CString:pUserInfo->szSurname
			     maxLength:EU_SURNAME_MAX_LENGTH] ||
		![userInfo.givenname
		  getCP1251CString:pUserInfo->szGivenname
			     maxLength:EU_GIVENNAME_MAX_LENGTH] ||
		![userInfo.email
		  getCP1251CString:pUserInfo->szEMail
			     maxLength:EU_EMAIL_MAX_LENGTH] ||
		![userInfo.dns
		  getCP1251CString:pUserInfo->szDNS
			     maxLength:EU_ADDRESS_MAX_LENGTH] ||
		![userInfo.edrpouCode
		  getCP1251CString:pUserInfo->szEDRPOUCode
			     maxLength:EU_EDRPOU_MAX_LENGTH] ||
		![userInfo.drfoCode
		  getCP1251CString:pUserInfo->szDRFOCode
			     maxLength:EU_DRFO_MAX_LENGTH] ||
		![userInfo.nbuCode
		  getCP1251CString:pUserInfo->szNBUCode
			     maxLength:EU_NBU_MAX_LENGTH] ||
		![userInfo.spfmCode
		  getCP1251CString:pUserInfo->szSPFMCode
			     maxLength:EU_SPFM_MAX_LENGTH] ||
		![userInfo.oCode
		  getCP1251CString:pUserInfo->szOCode
			     maxLength:EU_O_CODE_MAX_LENGTH] ||
		![userInfo.ouCode
		  getCP1251CString:pUserInfo->szOUCode
			     maxLength:EU_OU_CODE_MAX_LENGTH] ||
		![userInfo.userCode
		  getCP1251CString:pUserInfo->szUserCode
			     maxLength:EU_USER_CODE_MAX_LENGTH] ||
		![userInfo.upn
		  getCP1251CString:pUserInfo->szUPN
			     maxLength:EU_UPN_MAX_LENGTH] ||
		![userInfo.unzr
		  getCP1251CString:pUserInfo->szUNZR
			     maxLength:EU_UNZR_MAX_LENGTH] ||
		![userInfo.country
		  getCP1251CString:pUserInfo->szCountry
			     maxLength:EU_COUNTRY_MAX_LENGTH])
	{
		return NO;
	}
	
	return YES;
}

- (BOOL) makeRequestInfo:(EURequestType) type
					data:(PBYTE) pbData
			  dataLength:(DWORD) dwDataLength
					name:(char* ) pszName
			 requestInfo:(EURequestInfo **) info
				   error:(NSError **) error
{
	DWORD dwError;
	PEU_CR_INFO pInfo;
	EURequestInfo *request = [[EURequestInfo alloc] init];

	*error = nil;

	dwError = EUGetCRInfo(pbData, dwDataLength, &pInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	request.type = type;
	request.data = [NSData dataWithBytes:pbData length:dwDataLength];
	request.name = [NSString stringWithCP1251String:pszName];
	request.isFilled = pInfo->bFilled ? YES : NO;
	
	request.version = pInfo->dwVersion;
	
	request.isSimple = pInfo->bSimple;

	request.subject = [NSString stringWithCP1251String:pInfo->pszSubject];
	request.subjCN = [NSString stringWithCP1251String:pInfo->pszSubjCN];
	request.subjOrg = [NSString stringWithCP1251String:pInfo->pszSubjOrg];
	request.subjOrgUnit = [NSString stringWithCP1251String:pInfo->pszSubjOrgUnit];
	request.subjTitle = [NSString stringWithCP1251String:pInfo->pszSubjTitle];
	request.subjState = [NSString stringWithCP1251String:pInfo->pszSubjState];
	request.subjLocality = [NSString stringWithCP1251String:pInfo->pszSubjLocality];
	request.subjFullName = [NSString stringWithCP1251String:pInfo->pszSubjFullName];
	request.subjAddress = [NSString stringWithCP1251String:pInfo->pszSubjAddress];
	request.subjPhone = [NSString stringWithCP1251String:pInfo->pszSubjPhone];
	request.subjEMail = [NSString stringWithCP1251String:pInfo->pszSubjEMail];
	request.subjDNS = [NSString stringWithCP1251String:pInfo->pszSubjDNS];
	request.subjEDRPOUCode = [NSString stringWithCP1251String:pInfo->pszSubjEDRPOUCode];
	request.subjDRFOCode = [NSString stringWithCP1251String:pInfo->pszSubjDRFOCode];
	request.subjNBUCode = [NSString stringWithCP1251String:pInfo->pszSubjNBUCode];
	request.subjSPFMCode = [NSString stringWithCP1251String:pInfo->pszSubjSPFMCode];
	request.subjOCode = [NSString stringWithCP1251String:pInfo->pszSubjOCode];
	request.subjOUCode = [NSString stringWithCP1251String:pInfo->pszSubjOUCode];
	request.subjUserCode = [NSString stringWithCP1251String:pInfo->pszSubjUserCode];

	request.isCertTimes = pInfo->bCertTimes ? YES : NO;
	request.certBeginTime = [self dateFromLocalTime:&pInfo->stCertBeginTime];
	request.certEndTime = [self dateFromLocalTime:&pInfo->stCertEndTime];
	request.isPrivKeyTimes = pInfo->bPrivKeyTimes ? YES : NO;
	request.privKeyBeginTime = [self dateFromLocalTime:&pInfo->stPrivKeyBeginTime];
	request.privKeyEndTime = [self dateFromLocalTime:&pInfo->stPrivKeyEndTime];
	
	request.publicKeyType = (EUPublicKeyType) pInfo->dwPublicKeyType;
	
	request.publicKeyBits = pInfo->dwPublicKeyBits;
	request.publicKey = [NSString stringWithCP1251String:pInfo->pszPublicKey];
	request.rsaModul = [NSString stringWithCP1251String:pInfo->pszRSAModul];
	request.rsaExponent = [NSString stringWithCP1251String:pInfo->pszRSAExponent];

	request.publicKeyID = [NSString stringWithCP1251String:pInfo->pszPublicKeyID];
	
	request.extKeyUsages = [NSString stringWithCP1251String:pInfo->pszExtKeyUsages];
	
	request.crlDistribPoint1 = [NSString stringWithCP1251String:pInfo->pszCRLDistribPoint1];
	request.crlDistribPoint2 = [NSString stringWithCP1251String:pInfo->pszCRLDistribPoint2];
	
	request.isSubjType = pInfo->bSubjType ? YES : NO;
	request.subjType = pInfo->dwSubjType;
	request.subjSubType = pInfo->dwSubjSubType;
	
	request.isSelfSigned = pInfo->bSelfSigned ? YES : NO;
	request.signIssuer = [NSString stringWithCP1251String:pInfo->pszSignIssuer];
	request.signSerial = [NSString stringWithCP1251String:pInfo->pszSignSerial];
	
	request.subjUNZR = [NSString stringWithCP1251String:pInfo->pszSubjUNZR];

	request.subjCountry = [NSString stringWithCP1251String:pInfo->pszSubjCountry];

	request.isQSCD = pInfo->bQSCD ? YES : NO;

	if (info)
		*info = request;

	EUFreeCRInfo(pInfo);

	return YES;
}

- (BOOL) makeKeyMedia:(PEU_KEY_MEDIA) pKeyMedia
			typeIndex:(NSInteger) typeIndex
		  deviceIndex:(NSInteger) deviceIndex
			 password:(NSString *) password
{
	pKeyMedia->dwTypeIndex = (DWORD) typeIndex;
	pKeyMedia->dwDevIndex = (DWORD) deviceIndex;
	
	if (![password getCP1251CString:pKeyMedia->szPassword
						  maxLength:EU_PASS_MAX_LENGTH])
	{
		return NO;
	}

	return YES;
}

- (EUSCClientStatistic *) makeSCClientStatistic:(PEU_SCC_STATISTIC) pStatistic
{
	EUSCClientStatistic *statistic;
	
	statistic = [[EUSCClientStatistic alloc] init];
	statistic.activeSessions = [NSNumber
		numberWithLongLong:pStatistic->dwlActiveSessions];
	statistic.gatedSessions = [NSNumber
		numberWithLongLong:pStatistic->dwlGatedSessions];
	statistic.protectedData = [NSNumber
		numberWithLongLong:pStatistic->dwlProtectedData];
	statistic.unprotectedData = [NSNumber
		numberWithLongLong:pStatistic->dwlUnprotectedData];
	
	return statistic;
}

- (BOOL) makeJKSPrivateKeyInfo: (char *) pszKeyAlias
					privateKey: (PBYTE) pbPrivateKey
			  privateKeyLength: (DWORD) dwPrivateKeyLength
			 certificatesCount: (DWORD) dwCertificatesCount
				  certificates: (PBYTE *) ppbCertificates
		  certificatesLengthes: (DWORD *) pdwCertificateLengthes
			 jksPrivateKeyInfo: (EUJKSPrivateKeyInfo **) jksKey
						 error: (NSError **) error
{
	DWORD				dwError;
	PEU_CERT_INFO_EX	pInfoEx;
	EUJKSPrivateKeyInfo	*key = [[EUJKSPrivateKeyInfo alloc] init];
	EUCertificate		*certificate;
	NSMutableArray<EUCertificate *>
						*certificates = [NSMutableArray array];

	*error = nil;

	for (DWORD dwI = 0; dwI < dwCertificatesCount; dwI++)
	{
		dwError = EUParseCertificateEx(
			ppbCertificates[dwI], pdwCertificateLengthes[dwI],
			&pInfoEx);
		if (dwError != EU_ERROR_NONE)
		{
			*error = [self makeError:dwError];
			return NO;
		}
		
		if (pInfoEx->dwSubjType == EU_SUBJECT_TYPE_END_USER)
		{
			certificate = [self makeCertificate:ppbCertificates[dwI]
							  certificateLength:pdwCertificateLengthes[dwI]
										 infoEx:pInfoEx];
			[certificates addObject:certificate];
		}

		EUFreeCertificateInfoEx(pInfoEx);
	}

	key.alias = [NSString stringWithCP1251String:pszKeyAlias];
	key.privateKey = [NSData dataWithBytes:pbPrivateKey length:dwPrivateKeyLength];
	key.certificates = [NSArray arrayWithArray:certificates];

	if (jksKey)
		*jksKey = key;

	return YES;
}

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
				   userInfo:(EUUserInfo * _Nullable) _userInfo
			   extKeyUsages:(NSString * _Nullable) extKeyUsages
				 privateKey:(NSData *_Nullable *_Nullable) privateKey
				   requests:(NSArray<EURequestInfo *>* _Nullable * _Nullable) _requests
					  error:(NSError **) error
{
	DWORD           dwError;
	EU_KEY_MEDIA	keyMedia;
	EU_USER_INFO	userInfo;
	char*			pszExtKeyUsages;
	PBYTE           pbPrivKey = NULL;
	DWORD           dwPrivKey = 0;
	PBYTE           pbUARequest = NULL;
	DWORD           dwUARequest = 0;
	char            szUARequest[MAX_PATH * 4 + 1];
	PBYTE           pbUAKEPRequest = NULL;
	DWORD           dwUAKEPRequest = 0;
	char            szUAKEPRequest[MAX_PATH * 4 + 1];
	PBYTE           pbRSARequest = NULL;
	DWORD           dwRSARequest = 0;
	char            szRSARequest[MAX_PATH * 4 + 1];
	PBYTE           pbECDSARequest = NULL;
	DWORD           dwECDSARequest = 0;
	char            szECDSARequest[MAX_PATH * 4 + 1];
	BOOL            bGenBinary;
	BOOL            bGenUA;
	BOOL            bGenUAKEP;
	BOOL            bGenRSA;
	BOOL            bGenECDSA;
	EURequestInfo   *request;
	NSMutableArray 	*requests = [NSMutableArray array];
	
	*error = nil;
	
	if (![self makeKeyMedia:&keyMedia
				  typeIndex:typeIndex
				deviceIndex:deviceIndex
				   password:password])
	{
		*error = [self makeError:EU_ERROR_BAD_PARAMETER];
		return NO;
	}
	
	bGenBinary = privateKey != nil;
	
	bGenUA = (uaKeysType != EUKeysTypeNone);
	bGenUAKEP = bGenUA &&
		(uaKEPKeysSpec != EUKeysLengthKEPUA_None);

	bGenRSA = (intKeysType & EUKeysTypeRSAWithSHA) != 0;
	bGenECDSA = (intKeysType & EUKeysTypeECDSAWithSHA) != 0;
	
	if (_userInfo != nil &&
		![self makeUserInfo:_userInfo cUserInfo:&userInfo])
	{
		*error = [self makeError:EU_ERROR_BAD_PARAMETER];
		return NO;
	}
	
	pszExtKeyUsages = (extKeyUsages != nil) ?
		(char *) [extKeyUsages cStringUsingEncoding:NSWindowsCP1251StringEncoding] :
		NULL;
	if (extKeyUsages != nil && pszExtKeyUsages == NULL)
	{
		*error = [self makeError:EU_ERROR_BAD_PARAMETER];
		return NO;
	}
	
	dwError = EUGeneratePrivateKey2(
		&keyMedia, isSetKeyMediaPassword ? TRUE : FALSE,
		(DWORD) uaKeysType, (DWORD) uaDSKeysSpec,
		(DWORD) uaKEPKeysSpec, NULL,
		(DWORD) intKeysType,
		(DWORD) rsaKeysSpec, NULL,
		(DWORD) ecdsaKeysSpec, NULL,
		_userInfo != nil ? &userInfo : NULL,
		extKeyUsages != nil ? pszExtKeyUsages : NULL,
		bGenBinary ? &pbPrivKey : NULL,
		bGenBinary ? &dwPrivKey : NULL,
		NULL, NULL,
		bGenUA ? &pbUARequest : NULL,
		bGenUA ?  &dwUARequest : NULL,
		bGenUA ? szUARequest : NULL,
		bGenUAKEP ? &pbUAKEPRequest : NULL,
		bGenUAKEP ? &dwUAKEPRequest : NULL,
		bGenUAKEP ? szUAKEPRequest : NULL,
		bGenRSA ? &pbRSARequest : NULL,
		bGenRSA ? &dwRSARequest : NULL,
		bGenRSA ? szRSARequest : NULL,
		bGenECDSA ? &pbECDSARequest : NULL,
		bGenECDSA ? &dwECDSARequest : NULL,
		bGenECDSA ? szECDSARequest : NULL);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (bGenBinary && privateKey)
		*privateKey = [NSData dataWithBytes:pbPrivKey length:dwPrivKey];

	if (bGenBinary)
		EUFreeMemory(pbPrivKey);

	requests = [NSMutableArray array];
	
	if (bGenUA)
	{
		if (![self makeRequestInfo:EURequestTypeDSUA
							  data:pbUARequest
						dataLength:dwUARequest
							  name:szUARequest
					   requestInfo:&request
							 error:error])
		{
			EUFreeMemory(pbUARequest);

			if (bGenUAKEP)
				EUFreeMemory(pbUAKEPRequest);
			if (bGenRSA)
				EUFreeMemory(pbRSARequest);
			if (bGenECDSA)
				EUFreeMemory(pbECDSARequest);
			
			return NO;
		}
		
		EUFreeMemory(pbUARequest);
		
		[requests addObject:request];
	}
	
	if (bGenUAKEP)
	{
		if (![self makeRequestInfo:EURequestTypeKEPUA
							  data:pbUAKEPRequest
						dataLength:dwUAKEPRequest
							  name:szUAKEPRequest
					   requestInfo:&request
							 error:error])
		{
			EUFreeMemory(pbUAKEPRequest);
			if (bGenRSA)
				EUFreeMemory(pbRSARequest);
			if (bGenECDSA)
				EUFreeMemory(pbECDSARequest);
			
			return NO;
		}
		
		EUFreeMemory(pbUAKEPRequest);
		
		[requests addObject:request];
	}
	
	if (bGenRSA)
	{
		if (![self makeRequestInfo:EURequestTypeRSA
							  data:pbRSARequest
						dataLength:dwRSARequest
							  name:szRSARequest
					   requestInfo:&request
							 error:error])
		{
			EUFreeMemory(pbRSARequest);
			if (bGenECDSA)
				EUFreeMemory(pbECDSARequest);
			
			return NO;
		}
		
		EUFreeMemory(pbRSARequest);

		[requests addObject:request];
	}
	
	if (bGenECDSA)
	{
		if (![self makeRequestInfo:EURequestTypeECDSA
							  data:pbECDSARequest
						dataLength:dwECDSARequest
							  name:szECDSARequest
					   requestInfo:&request
							 error:error])
		{
			EUFreeMemory(pbECDSARequest);
			
			return NO;
		}
		
		EUFreeMemory(pbECDSARequest);

		[requests addObject:request];
	}
	
	if (_requests)
		*_requests = [NSArray arrayWithArray:requests];

	return YES;
}

- (BOOL) readPrivateKeyInternal:(EUContext *) context
					 privateKey:(NSData *) privateKey
					  typeIndex:(NSInteger) typeIndex
					deviceIndex:(NSInteger) deviceIndex
					   password:(NSString *) password
				   certificates:(NSArray<NSData *>* _Nullable) certificates
					 caIssuerCN:(NSString * _Nullable) caIssuerCN
			  privateKeyContext:(EUPrivateKeyContext *_Nullable *_Nullable) pkContext
						  error:(NSError **) error
{
	DWORD           dwError;
	EU_KEY_MEDIA	keyMedia;
	PVOID 			pvPKContext = NULL;
	const char*		pszPassword = NULL;
	EUCASettings    *caSettings = nil;
	
	*error = nil;

	if (privateKey == nil &&
		![self makeKeyMedia:&keyMedia
				  typeIndex:typeIndex
				deviceIndex:deviceIndex
				   password:password])
	{
		*error = [self makeError:EU_ERROR_BAD_PARAMETER];
		return NO;
	}
	
	if (privateKey != nil)
	{
		pszPassword = [password
			cStringUsingEncoding:NSWindowsCP1251StringEncoding];
	}
	
	if (certificates)
	{
		for (NSData *certificate in certificates)
		{
			if (![self saveCertificate:certificate error:error])
				return NO;
		}
	}
	
	if (caIssuerCN)
	{
		for (EUCASettings *ca in self.CAs)
		{
			for (NSString *issuerCN in ca.issuerCNs)
			{
				if (![caIssuerCN isEqualToString:issuerCN])
					continue;
				
				caSettings = ca;
				break;
			}
			
			if (caSettings != nil)
				break;
		}
		
		if (caSettings.cmpAddress != nil &&
			![caSettings.cmpAddress isEqualToString:@""])
		{
			PBYTE       pbPKeyInfo;
			DWORD       dwPKeyInfoLength;
			PBYTE       pbCerts;
			DWORD       dwCertsLength;
			char        szAddresses[EU_ADDRESS_MAX_LENGTH + 1];
			char        szPorts[EU_PORT_MAX_LENGTH + 1];
			const char* pszCMPAddress = [caSettings.cmpAddress
				cStringUsingEncoding:NSWindowsCP1251StringEncoding];

			memset(szAddresses, 0, EU_ADDRESS_MAX_LENGTH + 1);
			strcpy(szAddresses, pszCMPAddress);

			memset(szPorts, 0, EU_PORT_MAX_LENGTH + 1);
			strcpy(szPorts, "80");

			if (privateKey)
			{
				dwError = EUGetKeyInfoBinary(
					(PBYTE) privateKey.bytes, (DWORD) privateKey.length,
					(char *) pszPassword, &pbPKeyInfo, &dwPKeyInfoLength);
				if (dwError != EU_ERROR_NONE)
				{
					*error = [self makeError:dwError];
					return NO;
				}
			}
			else
			{
				dwError = EUGetKeyInfo(
					&keyMedia, &pbPKeyInfo, &dwPKeyInfoLength);
				if (dwError != EU_ERROR_NONE)
				{
					*error = [self makeError:dwError];
					return NO;
				}
			}
			
			dwError = EUGetCertificatesByKeyInfo(
				pbPKeyInfo, dwPKeyInfoLength,
				szAddresses, szPorts, &pbCerts, &dwCertsLength);
			if (dwError != EU_ERROR_NONE)
			{
				EUFreeMemory(pbPKeyInfo);
				
				*error = [self makeError:dwError];
				return NO;
			}
			
			EUFreeMemory(pbPKeyInfo);
			
			dwError = EUSaveCertificates(pbCerts, dwCertsLength);
			if (dwError != EU_ERROR_NONE)
			{
				EUFreeMemory(pbCerts);
				
				*error = [self makeError:dwError];
				return NO;
			}

			EUFreeMemory(pbCerts);
		}
	}
	
	if (privateKey)
	{
		if (context)
		{
			dwError = EUCtxReadPrivateKeyBinary(context.handle,
				(PBYTE) privateKey.bytes, (DWORD) privateKey.length,
				(char *) pszPassword, &pvPKContext, NULL);
		}
		else
		{
			dwError = EUReadPrivateKeyBinary(
				(PBYTE) privateKey.bytes, (DWORD) privateKey.length,
				(char *) pszPassword, NULL);
		}
	}
	else
	{
		if (context)
		{
			dwError = EUCtxReadPrivateKey(
				context.handle, &keyMedia, &pvPKContext, NULL);
		}
		else
		{
			dwError = EUReadPrivateKey(&keyMedia, NULL);
		}
	}
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (context)
	{
		if (pkContext)
			*pkContext = [EUPrivateKeyContext context:pvPKContext];
		else
			EUCtxFreePrivateKey(pvPKContext);
	}
	
	return YES;
}

#pragma mark Public methods

- (BOOL) isInitialized
{
    return EUIsInitialized() ? YES : NO;
}

- (BOOL) initialize:(NSData *) settings
       certificates:(NSData *) certificates
              error:(NSError **) error
{
    DWORD   dwError;
    
    *error = nil;
    
    if (!EUIsInitialized())
    {
        EUSetUIMode(FALSE);
        dwError = EUInitialize();
        if (dwError != EU_ERROR_NONE)
        {
            *error = [self makeError:dwError];
            return NO;
        }
        
        EUSetUIMode(FALSE);
        
        dwError = [self setSettings:settings
                       certificates:certificates];
        if (dwError != EU_ERROR_NONE)
        {
            EUFinalize();
            
            *error = [self makeError:dwError];
            return NO;
        }
    }
    
    return YES;
}

- (void) finalize
{
	EUFinalize();
}

- (NSArray<EUCASettings*>*) getCAs
{
    return self.CAs;
}

- (BOOL) setModeSettings:(BOOL) isOffline
				   error:(NSError **) error
{
	DWORD			dwError;
	
	*error = nil;

	dwError = EUSetModeSettings(isOffline ? TRUE : FALSE);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	return YES;
}

- (BOOL) protectData:(NSData *) data
		  byPassword:(NSString *) password
	   protectedData:(NSData *_Nullable *_Nullable) protectedData
			   error:(NSError **) error
{
    DWORD           dwError;
    const char*     pszPassword;
    PBYTE           pbProtectedData;
    DWORD           dwProtectedDataLength;
    
    *error = nil;
      
    pszPassword = [password
        cStringUsingEncoding:NSWindowsCP1251StringEncoding];

    dwError = EUProtectDataByPassword(
        (PBYTE) data.bytes, (DWORD) data.length,
        (char *) pszPassword, NULL, &pbProtectedData, &dwProtectedDataLength);
    if (dwError != EU_ERROR_NONE)
    {
        *error = [self makeError:dwError];
        return NO;
    }

    if (protectedData)
        *protectedData = [NSData dataWithBytes:pbProtectedData length:dwProtectedDataLength];
    
    EUFreeMemory(pbProtectedData);

    return YES;
}

- (BOOL) unprotectData:(NSData *) protectedData
			byPassword:(NSString *) password
				  data:(NSData *_Nullable *_Nullable) data
				 error:(NSError **) error;
{
    DWORD           dwError;
    const char*     pszPassword;
    PBYTE           pbData;
    DWORD           dwDataLength;
    
    *error = nil;
      
    pszPassword = [password
        cStringUsingEncoding:NSWindowsCP1251StringEncoding];

    dwError = EUUnprotectDataByPassword(
        NULL, (PBYTE) protectedData.bytes, (DWORD) protectedData.length,
        (char *) pszPassword, &pbData, &dwDataLength);
    if (dwError != EU_ERROR_NONE)
    {
        *error = [self makeError:dwError];
        return NO;
    }

    if (data)
        *data = [NSData dataWithBytes:pbData length:dwDataLength];
    
    EUFreeMemory(pbData);

    return YES;
}

- (BOOL) parseCertificateEx:(NSData *) certificate
				 certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
					  error:(NSError **) error
{
	DWORD				dwError;
	PEU_CERT_INFO_EX	pInfoEx;
	
	*error = nil;
	
	dwError = EUParseCertificateEx(
		(PBYTE) certificate.bytes, (DWORD) certificate.length,
		&pInfoEx);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (certInfoEx)
		*certInfoEx = [self makeCertificateInfoEx:pInfoEx];

	EUFreeCertificateInfoEx(pInfoEx);

	return YES;
}

- (BOOL) saveCertificate:(NSData *) certificate
				   error:(NSError **) error
{
	DWORD			dwError;
	
	*error = nil;
	
	dwError = EUSaveCertificate(
		(PBYTE) certificate.bytes, (DWORD) certificate.length);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (BOOL) saveCertificates:(NSData *) certificates
					error:(NSError **) error
{
	DWORD			dwError;
	
	*error = nil;
	
	dwError = EUSaveCertificates(
		(PBYTE) certificates.bytes, (DWORD) certificates.length);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (BOOL) getCertificateChain:(NSData *) certificate
			  caCertificates:(NSArray<NSData *>* _Nullable * _Nullable) caCertificates
					   error:(NSError **) error
{
	DWORD				dwError;
	DWORD				dwCACertificatesCount;
	PBYTE				*ppbCACertificates;
	PDWORD				pdwCACertificatesLengthes;

	*error = nil;

	dwError = EUGetCertificateChain(
		(PBYTE) certificate.bytes, (DWORD) certificate.length,
		&dwCACertificatesCount, &ppbCACertificates, &pdwCACertificatesLengthes);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (caCertificates)
	{
		*caCertificates = [self makeArrayOfByteArrays:dwCACertificatesCount 
											   arrays:ppbCACertificates
									   arraysLengthes:pdwCACertificatesLengthes];
	}

	EUFreeCertificatesArray(dwCACertificatesCount,
		ppbCACertificates, pdwCACertificatesLengthes);

	return YES;
}


- (BOOL) getTSP:(EUCtxHashAlgo) hashAlgo
		   hash:(NSData *) hash
   byAccessInfo:(NSString *) accessInfo
 accessInfoPort:(NSString *) accessInfoPort
			tsp:(NSData *_Nullable *_Nullable) tsp
		  error:(NSError **) error
{
	DWORD           dwError;
	const char*		pszAccessInfo;
	const char*		pszAccessInfoPort;
	PBYTE   		pbTSP;
	DWORD   		dwTSPLength;

	*error = nil;

	pszAccessInfo = [accessInfo
		cStringUsingEncoding:NSWindowsCP1251StringEncoding];
	pszAccessInfoPort = [accessInfoPort
		cStringUsingEncoding:NSWindowsCP1251StringEncoding];

	dwError = EUGetTSPByAccessInfo(
		(DWORD) hashAlgo, NULL, (PBYTE) hash.bytes, (DWORD) hash.length,
		(char *) pszAccessInfo, (char *) pszAccessInfoPort,
		&pbTSP, &dwTSPLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (tsp)
		*tsp = [NSData dataWithBytes:pbTSP length:dwTSPLength];

	EUFreeMemory(pbTSP);

	return YES;
}

- (BOOL) getOCSPResponse:(NSData *) certificate
			byAccessInfo:(NSString *) accessInfo
		  accessInfoPort:(NSString *) accessInfoPort
			ocspResponse:(NSData *_Nullable *_Nullable) ocspResponse
				   error:(NSError **) error
{
	DWORD			dwError;
	const char*		pszAccessInfo;
	const char*		pszAccessInfoPort;
	PBYTE			pbOCSPResponse;
	DWORD			dwOCSPResponseLength;

	*error = nil;

	pszAccessInfo = [accessInfo
		cStringUsingEncoding:NSWindowsCP1251StringEncoding];
	pszAccessInfoPort = [accessInfoPort
		cStringUsingEncoding:NSWindowsCP1251StringEncoding];

	dwError = EUGetOCSPResponseByAccessInfo(
		(PBYTE) certificate.bytes, (DWORD) certificate.length,
		(char *) pszAccessInfo, (char *) pszAccessInfoPort,
		&pbOCSPResponse, &dwOCSPResponseLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (ocspResponse)
	{
		*ocspResponse = [NSData dataWithBytes:pbOCSPResponse 
									   length:dwOCSPResponseLength];
	}
	
	EUFreeMemory(pbOCSPResponse);

	return YES;
}

- (BOOL) getJKSPrivateKeys:(NSData *) privateKey
				   jksKeys:(NSArray<EUJKSPrivateKeyInfo *> *_Nullable*_Nullable) jksKeys
					 error:(NSError **) error
{
	DWORD			dwError;
	DWORD			dwKeyIndex;
	char			*pszKeyAlias;
	PBYTE			pbPrivateKey;
	DWORD			dwPrivateKeyLength;
	DWORD			dwCertificatesCount;
	PBYTE			*ppbCertificates;
	PDWORD			pdwCertificatesLengthes;
	EUJKSPrivateKeyInfo	*jksKey;
	NSMutableArray<EUJKSPrivateKeyInfo *> *keys = [NSMutableArray array];

	*error = nil;

	dwKeyIndex = 0;
	while (YES)
	{
		dwError = EUEnumJKSPrivateKeys(
			(PBYTE) privateKey.bytes, (DWORD) privateKey.length,
			dwKeyIndex, &pszKeyAlias);
		if (dwError != EU_ERROR_NONE)
		{
			if (dwError == EU_WARNING_END_OF_ENUM)
				break;

			*error = [self makeError:dwError];
			return NO;
		}
		
		dwError = EUGetJKSPrivateKey(
			(PBYTE) privateKey.bytes, (DWORD) privateKey.length,
			pszKeyAlias, &pbPrivateKey, &dwPrivateKeyLength,
			&dwCertificatesCount,
			&ppbCertificates, &pdwCertificatesLengthes);
		if (dwError != EU_ERROR_NONE)
		{
			EUFreeMemory((PBYTE) pszKeyAlias);

			*error = [self makeError:dwError];
			return NO;
		}
		
		if (![self makeJKSPrivateKeyInfo:pszKeyAlias
							  privateKey:pbPrivateKey
						privateKeyLength:dwPrivateKeyLength
					   certificatesCount:dwCertificatesCount
							certificates:ppbCertificates
					certificatesLengthes:pdwCertificatesLengthes
					   jksPrivateKeyInfo:&jksKey
								   error:error])
		{
			EUFreeMemory((PBYTE) pszKeyAlias);
			EUFreeMemory(pbPrivateKey);
			EUFreeCertificatesArray(dwCertificatesCount,
				ppbCertificates, pdwCertificatesLengthes);

			return NO;
		}

		[keys addObject:jksKey];

		EUFreeMemory((PBYTE) pszKeyAlias);
		EUFreeMemory(pbPrivateKey);
		EUFreeCertificatesArray(dwCertificatesCount,
			ppbCertificates, pdwCertificatesLengthes);

		dwKeyIndex++;
	}

	if (jksKeys)
		*jksKeys = [NSArray arrayWithArray:keys];

	return YES;
}

- (BOOL) enumKeyMediaTypes:(NSArray<NSString *>*_Nullable*_Nullable) keyMediaTypes
					 error:(NSError **) error
{
	DWORD			dwError;
	DWORD			dwTypeIndex;
	char			szType[EU_KEY_MEDIA_NAME_MAX_LENGTH];
	NSMutableArray<NSString *>
					*types = [NSMutableArray array];
	
	*error = nil;
	
	dwTypeIndex = 0;
	while (YES)
	{
		dwError = EUEnumKeyMediaTypes(dwTypeIndex, szType);
		if (dwError != EU_ERROR_NONE)
		{
			if (dwError == EU_WARNING_END_OF_ENUM)
				break;
			
			*error = [self makeError:dwError];
			return NO;
		}
		
		[types addObject:[NSString stringWithCP1251String:szType]];
		dwTypeIndex++;
	}
	
	if (keyMediaTypes)
		*keyMediaTypes = [NSArray arrayWithArray:types];
	
	return YES;
}

- (BOOL) enumKeyMediaDevicesForType:(NSInteger) keyMediaType
							devices:(NSArray<NSString *>* _Nullable * _Nullable) keyMediaDevices
							  error:(NSError **) error
{
	DWORD			dwError;
	DWORD			dwDeviceIndex;
	char			szDevice[EU_KEY_MEDIA_NAME_MAX_LENGTH];
	NSMutableArray<NSString *>
					*devices = [NSMutableArray array];
	
	*error = nil;
	
	dwDeviceIndex = 0;
	while (YES)
	{
		dwError = EUEnumKeyMediaDevices(
			(DWORD) keyMediaType, dwDeviceIndex, szDevice);
		if (dwError != EU_ERROR_NONE)
		{
			if (dwError == EU_WARNING_END_OF_ENUM)
				break;
			
			*error = [self makeError:dwError];
			return NO;
		}
		
		[devices addObject:[NSString stringWithCP1251String:szDevice]];
		dwDeviceIndex++;
	}
	
	if (keyMediaDevices)
		*keyMediaDevices = [NSArray arrayWithArray:devices];
	
	return YES;
}

- (BOOL) isPrivateKeyExists:(NSInteger) typeIndex
				deviceIndex:(NSInteger) deviceIndex
				   password:(NSString *) password
{
	DWORD           dwError;
	EU_KEY_MEDIA	keyMedia;
	int				bExist;
	  
	if (![self makeKeyMedia:&keyMedia
				  typeIndex:typeIndex
				deviceIndex:deviceIndex
				   password:password])
	{
		return NO;
	}
	
	dwError = EUIsPrivateKeyExists(&keyMedia, &bExist);
	if (dwError != EU_ERROR_NONE)
		return NO;
	
	return bExist ? YES : NO;
}

- (BOOL) destroyPrivateKey:(NSInteger) typeIndex
			   deviceIndex:(NSInteger) deviceIndex
				  password:(NSString *) password
					 error:(NSError **) error
{
	DWORD           dwError;
	EU_KEY_MEDIA	keyMedia;
	
	*error = nil;

	if (![self makeKeyMedia:&keyMedia
				  typeIndex:typeIndex
				deviceIndex:deviceIndex
				   password:password])
	{
		*error = [self makeError:EU_ERROR_BAD_PARAMETER];
		return NO;
	}

	dwError = EUDestroyPrivateKey(&keyMedia);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	return YES;
}

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
					  error:(NSError **) error
{
	return [self generatePrivateKey:typeIndex
						deviceIndex:deviceIndex
						   password:password
				setKeyMediaPassword:isSetKeyMediaPassword
						 uaKeysType:uaKeysType
					   uaDSKeysSpec:uaDSKeysSpec
					  uaKEPKeysSpec:uaKEPKeysSpec
						intKeysType:intKeysType
						rsaKeysSpec:rsaKeysSpec
					  ecdsaKeysSpec:ecdsaKeysSpec
						   userInfo:userInfo
					   extKeyUsages:extKeyUsages
						 privateKey:nil
						   requests:requests
							  error:error];
}

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
							error:(NSError **) error
{
	return [self generatePrivateKey:0
						deviceIndex:0
						   password:password
				setKeyMediaPassword:NO
						 uaKeysType:uaKeysType
					   uaDSKeysSpec:uaDSKeysSpec
					  uaKEPKeysSpec:uaKEPKeysSpec
						intKeysType:intKeysType
						rsaKeysSpec:rsaKeysSpec
					  ecdsaKeysSpec:ecdsaKeysSpec
						   userInfo:userInfo
					   extKeyUsages:extKeyUsages
						 privateKey:privateKey
						   requests:requests
							  error:error];
}

- (BOOL) isPrivateKeyReaded
{
	return (EUIsPrivateKeyReaded() == TRUE) ? YES : NO;
}

- (BOOL) readPrivateKey:(NSInteger) typeIndex
			deviceIndex:(NSInteger) deviceIndex
			   password:(NSString *) password
		   certificates:(NSArray<NSData *>* _Nullable) certificates
			 caIssuerCN:(NSString * _Nullable) caIssuerCN
				  error:(NSError **) error
{
	return [self readPrivateKeyInternal: nil
					 privateKey:nil
					  typeIndex:typeIndex
					deviceIndex:deviceIndex
					   password:password
				   certificates:certificates
					 caIssuerCN:caIssuerCN
			  privateKeyContext:nil
						  error:error];
}

- (BOOL) readPrivateKeyBinary:(NSData *) privateKey
                     password:(NSString *) password
                 certificates:(NSArray<NSData *>*) certificates
                   caIssuerCN:(NSString *) caIssuerCN
                        error:(NSError **) error
{
	return [self readPrivateKeyInternal: nil
					 privateKey:privateKey
					  typeIndex:0
					deviceIndex:0
					   password:password
				   certificates:certificates
					 caIssuerCN:caIssuerCN
			  privateKeyContext:nil
						  error:error];
}

- (BOOL) getOwnCertificateWithPublicKeyType:(EUPublicKeyType) keyType
								   keyUsage:(EUKeyUsage) keyUsage
								certificate:(NSData *_Nullable *_Nullable) certificate
									  error:(NSError **) error
{
	DWORD				dwIndex;
	PBYTE				pbCertificate;
	DWORD				dwCertificate;
	PEU_CERT_INFO_EX	pInfo;
	DWORD				dwError;

	*error = nil;

	dwIndex = 0;
	while (1)
	{
		dwError = EUEnumOwnCertificates(
			dwIndex, &pInfo);
		if (dwError != EU_ERROR_NONE)
		{
			*error = [self makeError:dwError];
			return NO;
		}

		if ((keyType != EUPubKeyUnknown &&
			((DWORD) keyType != pInfo->dwPublicKeyType)) ||
			(pInfo->dwKeyUsage & keyUsage) != keyUsage)
		{
			EUFreeCertificateInfoEx(pInfo);

			dwIndex++;

			continue;
		}

		dwError = EUGetCertificate(
			pInfo->pszIssuer, pInfo->pszSerial,
			NULL, &pbCertificate, &dwCertificate);
		if (dwError != EU_ERROR_NONE)
		{
			EUFreeCertificateInfoEx(pInfo);

			*error = [self makeError:dwError];
			return NO;
		}

		if (certificate)
			*certificate = [NSData dataWithBytes:pbCertificate length:dwCertificate];

		EUFreeCertificateInfoEx(pInfo);
		EUFreeMemory(pbCertificate);

		return YES;
	}
}

- (void) resetPrivateKey
{
	EUResetPrivateKey();
}

- (void) ctxFreePrivateKey:(EUPrivateKeyContext *) pkContext
{
	if (pkContext)
		EUCtxFreePrivateKey(pkContext.handle);
}

- (BOOL) ctxReadPrivateKey:(EUContext *) context
				 typeIndex:(NSInteger) typeIndex
			   deviceIndex:(NSInteger) deviceIndex
				  password:(NSString *) password
			  certificates:(NSArray<NSData *>* _Nullable) certificates
				caIssuerCN:(NSString * _Nullable) caIssuerCN
		 privateKeyContext:(EUPrivateKeyContext *_Nullable *_Nullable) pkContext
					 error:(NSError **) error
{
	return [self readPrivateKeyInternal:context
							 privateKey:nil
							  typeIndex:typeIndex
							deviceIndex:deviceIndex
							   password:password
						   certificates:certificates
							 caIssuerCN:caIssuerCN
					  privateKeyContext:pkContext
								  error:error];
}

- (BOOL) ctxReadPrivateKeyBinary:(EUContext *) context
					  privateKey:(NSData *) privateKey
						password:(NSString *) password
					certificates:(NSArray<NSData *>* _Nullable) certificates
					  caIssuerCN:(NSString * _Nullable) caIssuerCN
			   privateKeyContext:(EUPrivateKeyContext *_Nullable *_Nullable) pkContext
						   error:(NSError **) error
{
	return [self readPrivateKeyInternal:context
							 privateKey:privateKey
							  typeIndex:0
							deviceIndex:0
							   password:password
						   certificates:certificates
							 caIssuerCN:caIssuerCN
					  privateKeyContext:pkContext
								  error:error];
}

- (BOOL) ctxGetOwnCertificates:(EUPrivateKeyContext *) pkContext
				  certificates:(NSArray<EUCertificate *> *_Nullable *_Nullable) certificates
						 error:(NSError **) error
{
	DWORD           	dwError;
	DWORD				dwIndex = 0;
	PEU_CERT_INFO_EX	pInfoEx;
	PBYTE   			pbCert;
	DWORD   			dwCertLength;
	NSMutableArray<EUCertificate *> *certs = [NSMutableArray array];
	
	*error = nil;
	
	while (YES)
	{
		dwError = EUCtxEnumOwnCertificates(
			pkContext.handle, dwIndex,
			&pInfoEx, &pbCert, &dwCertLength);
		if (dwError != EU_ERROR_NONE)
		{
			if (dwError == EU_WARNING_END_OF_ENUM)
				break;

			*error = [self makeError:dwError];
			return NO;
		}
		
		[certs addObject:[self makeCertificate:pbCert
							 certificateLength:dwCertLength
										infoEx:pInfoEx]];

		EUCtxFreeCertificateInfoEx(pkContext.handle, pInfoEx);
		EUCtxFreeMemory(pkContext.handle, pbCert);
		
		dwIndex++;
	}
	
	if (certificates)
		*certificates = [NSArray arrayWithArray:certs];
	
	return YES;
}

- (BOOL) createEmptySign:(NSData *) data
					sign:(NSData *_Nullable *_Nullable) sign
				   error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbSign;
	DWORD			dwSignLength;
	
	*error = nil;
	
	dwError = EUCreateEmptySign(
		(PBYTE) (data ? data.bytes : NULL),
		(DWORD) (data ? data.length : NULL),
		NULL, &pbSign, &dwSignLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (sign)
		*sign = [NSData dataWithBytes:pbSign length:dwSignLength];

	EUFreeMemory(pbSign);

	return YES;
}

- (BOOL) createSignerBegin:(NSData *) certificate
					  hash:(NSData *) hash
					signer:(NSData *_Nullable *_Nullable) signer
				 attrsHash:(NSData *_Nullable *_Nullable) attrsHash
					 error:(NSError **) error
{
	DWORD			dwError;
	PBYTE			pbSigner;
	DWORD			dwSignerLength;
	PBYTE			pbAttrsHash;
	DWORD			dwAttrsHashLength;

	*error = nil;
	
	dwError = EUCreateSignerBegin(
		(PBYTE) certificate.bytes, (DWORD) certificate.length,
		(PBYTE) hash.bytes, (DWORD) hash.length,
		&pbSigner, &dwSignerLength, &pbAttrsHash, &dwAttrsHashLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (signer)
		*signer = [NSData dataWithBytes:pbSigner length:dwSignerLength];

	if (attrsHash)
		*attrsHash = [NSData dataWithBytes:pbAttrsHash length:dwAttrsHashLength];
	
	EUFreeMemory(pbSigner);
	EUFreeMemory(pbAttrsHash);

	return YES;
}

- (BOOL) createRevocationInfoAttributes:(NSInteger) revocationReferences
						  ocspResponses:(NSArray<NSData *>*) ocspResponses
			   revocationReferencesAttr:(NSData *_Nullable *_Nullable) revocationReferencesAttr
				   revocationValuesAttr:(NSData *_Nullable *_Nullable) revocationValuesAttr
								  error:(NSError **) error
{
	DWORD			dwError;
	DWORD			dwOCSPResponses;
	PBYTE			*ppbOCSPResponses;
	DWORD			*pdwOCSPResponsesLengthes;
	PBYTE			pbRevocationReferencesAttr;
	DWORD			dwRevocationReferencesAttrLength;
	PBYTE			pbRevocationValuesAttr;
	DWORD			dwRevocationValuesAttrLength;

	*error = nil;
	
	if (![self getArrayOfByteArrays:ocspResponses 
							  count:&dwOCSPResponses
							 arrays:&ppbOCSPResponses
					 arraysLengthes:&pdwOCSPResponsesLengthes])
	{
		*error = [self makeError:EU_ERROR_MEMORY_ALLOCATION];

		return NO;
	}
	
	dwError = EUCreateRevocationInfoAttributes(
		(DWORD) revocationReferences,
		dwOCSPResponses, ppbOCSPResponses, pdwOCSPResponsesLengthes,
		&pbRevocationReferencesAttr, &dwRevocationReferencesAttrLength,
		&pbRevocationValuesAttr, &dwRevocationValuesAttrLength);
	if (dwError != EU_ERROR_NONE)
	{
		[self freeArrayOfByteArrays:dwOCSPResponses
							 arrays:ppbOCSPResponses
					 arraysLengthes:pdwOCSPResponsesLengthes];
		
		*error = [self makeError:dwError];

		return NO;
	}

	[self freeArrayOfByteArrays:dwOCSPResponses
						 arrays:ppbOCSPResponses
				 arraysLengthes:pdwOCSPResponsesLengthes];

	if (revocationReferencesAttr)
	{
		*revocationReferencesAttr = [NSData 
			dataWithBytes:pbRevocationReferencesAttr 
				   length:dwRevocationReferencesAttrLength];
	}
	
	if (revocationValuesAttr)
	{
		*revocationValuesAttr = [NSData 
			dataWithBytes:pbRevocationValuesAttr 
				   length:dwRevocationValuesAttrLength];
	}

	EUFreeMemory(pbRevocationReferencesAttr);
	EUFreeMemory(pbRevocationValuesAttr);

	return YES;
}

- (BOOL) createCACertificateInfoAttributes:(NSArray<NSData *>*) caCertificates
				 certificateReferencesAttr:(NSData *_Nullable *_Nullable) certificateReferencesAttr
					 certificateValuesAttr:(NSData *_Nullable *_Nullable) certificateValuesAttr
									 error:(NSError **) error
{
	DWORD			dwError;
	DWORD			dwCACertificates;
	PBYTE			*ppbCACertificates;
	PDWORD			pdwCACertificatesLengthes;
	PBYTE			pbCertificateReferencesAttr;
	DWORD			dwCertificateReferencesAttrLength;
	PBYTE			pbCertificateValuesAttr;
	DWORD			dwCertificateValuesAttrLength;

	*error = nil;
	
	if (![self getArrayOfByteArrays:caCertificates 
							  count:&dwCACertificates
							 arrays:&ppbCACertificates
					 arraysLengthes:&pdwCACertificatesLengthes])
	{
		*error = [self makeError:EU_ERROR_MEMORY_ALLOCATION];

		return NO;
	}
	
	dwError = EUCreateCACertificateInfoAttributes(
		dwCACertificates, ppbCACertificates, pdwCACertificatesLengthes,
		&pbCertificateReferencesAttr, &dwCertificateReferencesAttrLength,
		&pbCertificateValuesAttr, &dwCertificateValuesAttrLength);
	if (dwError != EU_ERROR_NONE)
	{
		[self freeArrayOfByteArrays:dwCACertificates
							 arrays:ppbCACertificates
					 arraysLengthes:pdwCACertificatesLengthes];
		
		*error = [self makeError:dwError];

		return NO;
	}

	[self freeArrayOfByteArrays:dwCACertificates
						 arrays:ppbCACertificates
				 arraysLengthes:pdwCACertificatesLengthes];

	if (certificateReferencesAttr)
	{
		*certificateReferencesAttr = [NSData 
			dataWithBytes:pbCertificateReferencesAttr 
				   length:dwCertificateReferencesAttrLength];
	}
	
	if (certificateValuesAttr)
	{
		*certificateValuesAttr = [NSData 
			dataWithBytes:pbCertificateValuesAttr 
				   length:dwCertificateValuesAttrLength];
	}

	EUFreeMemory(pbCertificateReferencesAttr);
	EUFreeMemory(pbCertificateValuesAttr);

	return YES;
}

- (BOOL) appendSignerUnsignedAttribute:(NSData *) previousSigner
							   attrOID:(NSString *) attrOID
							 attrValue:(NSData *) attrValue
								signer:(NSData *_Nullable *_Nullable) signer
								 error:(NSError **) error;
{
	DWORD			dwError;
	const char*		pszAttrOID;
	PBYTE			pbSigner;
	DWORD			dwSignerLength;

	*error = nil;

	pszAttrOID = [attrOID cStringUsingEncoding:NSWindowsCP1251StringEncoding];

	dwError = EUAppendSignerUnsignedAttribute(
		NULL, (PBYTE) previousSigner.bytes, (DWORD) previousSigner.length,
		(char *) pszAttrOID, (PBYTE) attrValue.bytes, (DWORD) attrValue.length,
		NULL, &pbSigner, &dwSignerLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];

		return NO;
	}

	if (signer)
		*signer = [NSData dataWithBytes:pbSigner length:dwSignerLength];

	EUFreeMemory(pbSigner);

	return YES;
}

- (BOOL) createSignerEnd:(NSData *) unsignedSigner
			   signarure:(NSData *) signarure
				  signer:(NSData *_Nullable *_Nullable) signer
				   error:(NSError **) error
{
	DWORD			dwError;
	PBYTE			pbSigner;
	DWORD			dwSignerLength;

	*error = nil;
	
	dwError = EUCreateSignerEnd(
		(PBYTE) unsignedSigner.bytes, (DWORD) unsignedSigner.length,
		(PBYTE) signarure.bytes, (DWORD) signarure.length,
		&pbSigner, &dwSignerLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (signer)
		*signer = [NSData dataWithBytes:pbSigner length:dwSignerLength];

	EUFreeMemory(pbSigner);

	return YES;
}

- (BOOL) getSigner:(NSData *) sign
		 signIndex:(NSInteger) signIndex
			signer:(NSData *_Nullable *_Nullable) signer
			 error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbSigner;
	DWORD			dwSignerLength;
	
	*error = nil;

	dwError = EUGetSigner((DWORD) signIndex,
		NULL, (PBYTE) sign.bytes, (DWORD) sign.length,
		NULL, &pbSigner, &dwSignerLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signer)
		*signer = [NSData dataWithBytes:pbSigner length:dwSignerLength];

	EUFreeMemory(pbSigner);

	return YES;
}

- (BOOL) appendSigner:(NSData *) signer
		  certificate:(NSData *) certificate
		 previousSign:(NSData *) previousSign
				 sign:(NSData *_Nullable *_Nullable) sign
				error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbSign;
	DWORD			dwSignLength;
	
	*error = nil;
	
    dwError = EUAppendSigner(
        NULL, (PBYTE) signer.bytes, (DWORD) signer.length,
        (PBYTE) (certificate ? certificate.bytes : NULL),
        (DWORD) (certificate ? certificate.length : NULL),
        NULL, (PBYTE) previousSign.bytes, (DWORD) previousSign.length,
        NULL, &pbSign, &dwSignLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (sign)
		*sign = [NSData dataWithBytes:pbSign length:dwSignLength];

	EUFreeMemory(pbSign);

	return YES;
}

- (BOOL) getSignsCount:(NSData *) sign
			signsCount:(NSInteger *) signsCount
				 error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwSignsCount;
	
	*error = nil;
	
	dwError = EUGetSignsCount(
		NULL, (PBYTE) sign.bytes, (DWORD) sign.length,
		&dwSignsCount);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signsCount)
		*signsCount = (NSInteger) dwSignsCount;
	
	return YES;
}
- (BOOL) getSignerInfo:(NSData *) sign
			 signIndex:(NSInteger) signIndex
			certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
		   certificate:(NSData *_Nullable *_Nullable) certificate
				 error:(NSError **) error
{
	DWORD           	dwError;
	PEU_CERT_INFO_EX	pInfoEx;
	PBYTE				pbCert;
	DWORD				dwCertLength;
	
	*error = nil;
	
	dwError = EUGetSignerInfo(
		(DWORD) signIndex,
		NULL, (PBYTE) sign.bytes, (DWORD) sign.length,
		&pInfoEx, &pbCert, &dwCertLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (certInfoEx)
		*certInfoEx = [self makeCertificateInfoEx:pInfoEx];
	if (certificate)
		*certificate = [NSData dataWithBytes:pbCert length:dwCertLength];
	
	EUFreeCertificateInfoEx(pInfoEx);
	EUFreeMemory(pbCert);
	
	return YES;
}

- (BOOL) getSignTimeInfo:(NSData *) sign
			   signIndex:(NSInteger) signIndex
				timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
				   error:(NSError **) error
{
	DWORD           	dwError;
	PEU_TIME_INFO		pTimeInfo;
	
	*error = nil;
	
	dwError = EUGetSignTimeInfo((DWORD) signIndex,
		NULL, (PBYTE) sign.bytes, (DWORD) sign.length,
		&pTimeInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (timeInfo)
		*timeInfo = [self makeTimeInfo:pTimeInfo];
	
	EUFreeTimeInfo(pTimeInfo);
	
	return YES;
}

- (BOOL) signData:(NSData *) data
		 external:(BOOL) isExternal
		signature:(NSData *_Nullable *_Nullable) signature
			error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbSign;
	DWORD			dwSignLength;
	
	*error = nil;
	
	if (isExternal)
	{
		dwError = EUSignData(
			(PBYTE) data.bytes, (DWORD) data.length,
			NULL, &pbSign, &dwSignLength);
	}
	else
	{
		dwError = EUSignDataInternal(
			TRUE, (PBYTE) data.bytes, (DWORD) data.length,
			NULL, &pbSign, &dwSignLength);
	}
	
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signature)
		*signature = [NSData dataWithBytes:pbSign length:dwSignLength];

	EUFreeMemory(pbSign);
	
	return YES;
}

- (BOOL) verifyData:(NSData *) data
		  signIndex:(NSInteger) signIndex
		  signature:(NSData *) signature
		   signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
			  error:(NSError **) error
{
	DWORD           dwError;
	EU_SIGN_INFO	euSignInfo;
	
	*error = nil;
	
	dwError = EUVerifyDataSpecific(
		(PBYTE) data.bytes, (DWORD) data.length, (DWORD) signIndex,
		NULL, (PBYTE) signature.bytes, (DWORD) signature.length, &euSignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signInfo)
		*signInfo = [self makeSignInfo:&euSignInfo];
	
	EUFreeSignInfo(&euSignInfo);
	
	return YES;
}

- (BOOL) verifyDataInternal:(NSInteger) signIndex
				  signature:(NSData *) signature
					   data:(NSData *_Nullable *_Nullable) data
				   signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
					  error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbData;
	DWORD			dwDataLength;
	EU_SIGN_INFO	euSignInfo;
	
	*error = nil;
	
	dwError = EUVerifyDataInternalSpecific((DWORD) signIndex,
		NULL, (PBYTE) signature.bytes, (DWORD) signature.length,
		&pbData, &dwDataLength, &euSignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signInfo)
		*signInfo = [self makeSignInfo:&euSignInfo];
	if (data)
		*data = [NSData dataWithBytes:pbData length:dwDataLength];
	
	EUFreeMemory(pbData);
	EUFreeSignInfo(&euSignInfo);
	
	return YES;
}

- (void) sessionDestroy:(EUSessionContext *) session
{
	if (session != nil)
		EUSessionDestroy(session.handle);
}

- (BOOL) sessionGetPeerCertificateInfo:(EUSessionContext *) session
							  signInfo:(EUCertificateInfo *_Nullable *_Nullable) certInfo
								 error:(NSError **) error
{
	DWORD           dwError;
	EU_CERT_INFO	Info;
	
	*error = nil;
	
	dwError = EUSessionGetPeerCertificateInfo(
		session.handle, &Info);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (certInfo)
		*certInfo = [self makeCertificateInfo:&Info];

	EUFreeCertificateInfo(&Info);
	
	return YES;
}

- (BOOL) clientSessionCreateStep1:(NSUInteger) expireTime
						  session:(EUSessionContext **) session
					   clientData:(NSData **) clientData
							error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbClientData;
	DWORD			dwClientDataLength;
	PVOID			pvSession;
	
	*error = nil;
	
	dwError = EUClientSessionCreateStep1((DWORD) expireTime,
		&pvSession, &pbClientData, &dwClientDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (session)
		*session = [EUSessionContext context:pvSession];
	else
		EUSessionDestroy(pvSession);
	if (clientData)
		*clientData = [NSData dataWithBytes:pbClientData length:dwClientDataLength];
	
	EUFreeMemory(pbClientData);
	
	return YES;
}

- (BOOL) serverSessionCreateStep1:(NSUInteger) expireTime
					   clientData:(NSData *) clientData
						  session:(EUSessionContext **) session
					   serverData:(NSData **) serverData
							error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbServerData;
	DWORD			dwServerDataLength;
	PVOID			pvSession;
	
	*error = nil;
	
	dwError = EUServerSessionCreateStep1((DWORD) expireTime,
		(PBYTE) clientData.bytes, (DWORD) clientData.length,
		&pvSession, &pbServerData, &dwServerDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (session)
		*session = [EUSessionContext context:pvSession];
	else
		EUSessionDestroy(pvSession);
	if (serverData)
		*serverData = [NSData dataWithBytes:pbServerData length:dwServerDataLength];
	
	EUFreeMemory(pbServerData);
	
	return YES;
}

- (BOOL) serverSessionCreateStep1:(NSUInteger) expireTime
						  encAlgo:(EUSessionEncAlgo) encAlgo
					   clientData:(NSData *) clientData
						  session:(EUSessionContext **) session
					   serverData:(NSData **) serverData
							error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbServerData;
	DWORD			dwServerDataLength;
	PVOID			pvSession;
	
	*error = nil;
	
	dwError = EUServerSessionCreateStep1Ex(
		(DWORD) expireTime, (DWORD) encAlgo,
		(PBYTE) clientData.bytes, (DWORD) clientData.length,
		&pvSession, &pbServerData, &dwServerDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (session)
		*session = [EUSessionContext context:pvSession];
	else
		EUSessionDestroy(pvSession);
	if (serverData)
		*serverData = [NSData dataWithBytes:pbServerData length:dwServerDataLength];
	
	EUFreeMemory(pbServerData);
	
	return YES;
}

- (BOOL) clientSessionCreateStep2:(EUSessionContext *) session
					   serverData:(NSData *) serverData
					   clientData:(NSData **) clientData
							error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbClientData;
	DWORD			dwClientDataLength;

	*error = nil;
	
	dwError = EUClientSessionCreateStep2(session.handle,
		(PBYTE) serverData.bytes, (DWORD) serverData.length,
		&pbClientData, &dwClientDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (clientData)
		*clientData = [NSData dataWithBytes:pbClientData length:dwClientDataLength];
	
	EUFreeMemory(pbClientData);
	
	return YES;
}

- (BOOL) serverSessionCreateStep2:(EUSessionContext *) session
					   clientData:(NSData *) clientData
							error:(NSError **) error
{
	DWORD           dwError;

	*error = nil;
	
	dwError = EUServerSessionCreateStep2(session.handle,
		(PBYTE) clientData.bytes, (DWORD) clientData.length);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (BOOL) sessionEncrypt:(EUSessionContext *) session
				   data:(NSData *) data
		  encryptedData:(NSData **) encryptedData
				  error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbEncryptedData;
	DWORD			dwEncryptedDataLength;

	*error = nil;
	
	dwError = EUSessionEncrypt(session.handle,
		(PBYTE) data.bytes, (DWORD) data.length,
		&pbEncryptedData, &dwEncryptedDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (encryptedData)
	{
		*encryptedData = [NSData dataWithBytes:pbEncryptedData
										length:dwEncryptedDataLength];
	}

	EUFreeMemory(pbEncryptedData);
	
	return YES;
}

- (BOOL) sessionDecrypt:(EUSessionContext *) session
		  encryptedData:(NSData *) encryptedData
				   data:(NSData **) data
				  error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbData;
	DWORD			dwDataLength;

	*error = nil;
	
	dwError = EUSessionDecrypt(session.handle,
		(PBYTE) encryptedData.bytes, (DWORD) encryptedData.length,
		&pbData, &dwDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (data)
		*data = [NSData dataWithBytes:pbData length:dwDataLength];

	EUFreeMemory(pbData);
	
	return YES;
}

- (BOOL) sessionEncryptContinue:(EUSessionContext *) session
						   data:(NSMutableData *) data
						  error:(NSError **) error
{
	DWORD           dwError;

	*error = nil;
	
	dwError = EUSessionEncryptContinue(session.handle,
		(PBYTE) data.mutableBytes, (DWORD) data.length);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (BOOL) sessionDecryptContinue:(EUSessionContext *) session
						   data:(NSMutableData *) data
						  error:(NSError **) error
{
	DWORD           dwError;

	*error = nil;
	
	dwError = EUSessionDecryptContinue(session.handle,
		(PBYTE) data.mutableBytes, (DWORD) data.length);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (BOOL) asicSignDataWithASiCType:(EUASiCType) asicType
						 signType:(EUASiCSignType) signType
						signLevel:(NSInteger) signLevel
					   references:(NSArray<EUDataReference *> *) references
						 asicData:(NSData *_Nullable *_Nullable) asicData
							error:(NSError **) error
{
	DWORD           dwError;
	char* 			pszReferences;
	PBYTE			*ppbReferences;
	DWORD 			*pdwRerencesLengths;
	PBYTE			pbASiCData;
	DWORD			dwASiCDataLength;
	
	*error = nil;
	
	if (![self getReferences:references
			 referencesNames:&pszReferences
			  referencesData:&ppbReferences
		referencesDataLength:&pdwRerencesLengths])
	{
		*error = [self makeError:EU_ERROR_MEMORY_ALLOCATION];
		return NO;
	}
	
	dwError = EUASiCSignData(
		(DWORD) asicType, (DWORD) signType, (DWORD) signLevel,
		pszReferences, ppbReferences, pdwRerencesLengths,
		&pbASiCData, &dwASiCDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		[self freeReferencesNames:pszReferences
				   referencesData:ppbReferences
			 referencesDataLength:pdwRerencesLengths];
		
		*error = [self makeError:dwError];
		return NO;
	}
	
	[self freeReferencesNames:pszReferences
			   referencesData:ppbReferences
		 referencesDataLength:pdwRerencesLengths];
	
	if (asicData)
		*asicData = [NSData dataWithBytes:pbASiCData length:dwASiCDataLength];
	
	EUFreeMemory(pbASiCData);
	
	return YES;
}

- (BOOL) asicVerifyData:(NSData *) asicData
			  signIndex:(NSInteger) signIndex
			   signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
				  error:(NSError **) error
{
	DWORD           dwError;
	EU_SIGN_INFO	euSignInfo;
	
	*error = nil;
	
	dwError = EUASiCVerifyData((DWORD) signIndex,
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&euSignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signInfo)
		*signInfo = [self makeSignInfo:&euSignInfo];

	EUFreeSignInfo(&euSignInfo);
	
	return YES;
}

- (BOOL) asicGetASiCType:(NSData *) asicData
				asicType:(EUASiCType *) asicType
				   error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwASiCType;
	
	*error = nil;
	
	dwError = EUASiCGetASiCType(
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&dwASiCType);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (asicType)
		*asicType = (EUASiCType) dwASiCType;
	
	return YES;
}

- (BOOL) asicGetSignType:(NSData *) asicData
				signType:(EUASiCSignType *) signType
				   error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwSignType;
	
	*error = nil;
	
	dwError = EUASiCGetSignType(
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&dwSignType);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signType)
		*signType = (EUASiCSignType) dwSignType;
	
	return YES;
}

- (BOOL) asicGetSignsCount:(NSData *) asicData
				signsCount:(NSInteger *) signsCount
					 error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwSignsCount;
	
	*error = nil;
	
	dwError = EUASiCGetSignsCount(
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&dwSignsCount);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signsCount)
		*signsCount = (NSInteger) dwSignsCount;
	
	return YES;
}

- (BOOL) asicGetSignerInfo:(NSData *) asicData
				 signIndex:(NSInteger) signIndex
				certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
			   certificate:(NSData *_Nullable *_Nullable) certificate
					 error:(NSError **) error
{
	DWORD           	dwError;
	PEU_CERT_INFO_EX	pInfoEx;
	PBYTE				pbCert;
	DWORD				dwCertLength;
	
	*error = nil;
	
	dwError = EUASiCGetSignerInfo(
		(DWORD) signIndex,
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&pInfoEx, &pbCert, &dwCertLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (certInfoEx)
		*certInfoEx = [self makeCertificateInfoEx:pInfoEx];
	if (certificate)
		*certificate = [NSData dataWithBytes:pbCert length:dwCertLength];
	
	EUFreeCertificateInfoEx(pInfoEx);
	EUFreeMemory(pbCert);
	
	return YES;
}

- (BOOL) asicGetSignTimeInfo:(NSData *) asicData
			signIndex:(NSInteger) signIndex
			 timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
				error:(NSError **) error
{
	DWORD           	dwError;
	PEU_TIME_INFO		pTimeInfo;
	
	*error = nil;
	
	dwError = EUASiCGetSignTimeInfo((DWORD) signIndex,
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&pTimeInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (timeInfo)
		*timeInfo = [self makeTimeInfo:pTimeInfo];
	
	EUFreeTimeInfo(pTimeInfo);
	
	return YES;
}

- (BOOL) asicGetSignReferences:(NSData *) asicData
			  signIndex:(NSInteger) signIndex
		referencesNames:(NSArray <NSString *> *_Nullable *_Nullable) referencesNames
				  error:(NSError **) error
{
	DWORD           	dwError;
	char*				pszReferences;
	
	*error = nil;
	
	dwError = EUASiCGetSignReferences((DWORD) signIndex,
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		&pszReferences);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (referencesNames)
		*referencesNames = [self makeStringsArray:pszReferences];
	
	return YES;
}

- (BOOL) asicGetReference:(NSString *) name
		  asicData:(NSData *) asicData
	 referenceData:(NSData *_Nullable *_Nullable) referenceData
			 error:(NSError **) error
{
	DWORD           	dwError;
	const char*			pszName;
	PBYTE				pbData;
	DWORD				dwDataLength;
	
	*error = nil;
	
	pszName = [name cStringUsingEncoding:NSWindowsCP1251StringEncoding];
	
	dwError = EUASiCGetReference(
		(PBYTE) asicData.bytes, (DWORD) asicData.length,
		(char *) pszName, &pbData, &dwDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (referenceData)
		*referenceData = [NSData dataWithBytes:pbData length:dwDataLength];
	
	EUFreeMemory(pbData);
	
	return YES;
}

- (BOOL) xadesSignDataWithXAdESType:(EUXAdESType) xadesType
						  signLevel:(EUXAdESSignLevel) signLevel
						 references:(NSArray<EUDataReference *> *) references
						  xadesData:(NSData *_Nullable *_Nullable) xadesData
							  error:(NSError **) error
{
	DWORD           dwError;
	char* 			pszReferences;
	PBYTE			*ppbReferences;
	DWORD 			*pdwRerencesLengths;
	PBYTE			pbXAdESData;
	DWORD			dwXAdESDataLength;
	
	*error = nil;
	
	if (![self getReferences:references
			 referencesNames:&pszReferences
			  referencesData:&ppbReferences
		referencesDataLength:&pdwRerencesLengths])
	{
		*error = [self makeError:EU_ERROR_MEMORY_ALLOCATION];
		return NO;
	}
	
	dwError = EUXAdESSignData(
		(DWORD) xadesType, (DWORD) signLevel,
		pszReferences, ppbReferences, pdwRerencesLengths,
		&pbXAdESData, &dwXAdESDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		[self freeReferencesNames:pszReferences
				   referencesData:ppbReferences
			 referencesDataLength:pdwRerencesLengths];
		
		*error = [self makeError:dwError];
		return NO;
	}
	
	[self freeReferencesNames:pszReferences
			   referencesData:ppbReferences
		 referencesDataLength:pdwRerencesLengths];
	
	if (xadesData)
		*xadesData = [NSData dataWithBytes:pbXAdESData length:dwXAdESDataLength];
	
	EUFreeMemory(pbXAdESData);
	
	return YES;
}

- (BOOL) xadesVerifyData:(NSData *) xadesData
			   signIndex:(NSInteger) signIndex
			  references:(NSArray<EUDataReference *> *) references
				signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
				   error:(NSError **) error
{
	DWORD           dwError;
	char* 			pszReferences = NULL;
	PBYTE			*ppbReferences = NULL;
	DWORD 			*pdwRerencesLengths = NULL;
	EU_SIGN_INFO	euSignInfo;
	
	*error = nil;
	
	if (references != nil &&
		![self getReferences:references
			 referencesNames:&pszReferences
			  referencesData:&ppbReferences
		referencesDataLength:&pdwRerencesLengths])
	{
		*error = [self makeError:EU_ERROR_MEMORY_ALLOCATION];
		return NO;
	}
	
	dwError = EUXAdESVerifyData(
		pszReferences, ppbReferences, pdwRerencesLengths,
		(DWORD) signIndex, (PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		&euSignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		[self freeReferencesNames:pszReferences
				   referencesData:ppbReferences
			 referencesDataLength:pdwRerencesLengths];
		
		*error = [self makeError:dwError];
		return NO;
	}
	
	[self freeReferencesNames:pszReferences
			   referencesData:ppbReferences
		 referencesDataLength:pdwRerencesLengths];
	
	if (signInfo)
		*signInfo = [self makeSignInfo:&euSignInfo];
	
	EUFreeSignInfo(&euSignInfo);
	
	return YES;
}

- (BOOL) xadesGetType:(NSData *) xadesData
			 signType:(EUXAdESType *) signType
				error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwSignType;
	
	*error = nil;
	
	dwError = EUXAdESGetType(
		(PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		&dwSignType);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signType)
		*signType = (EUXAdESType) dwSignType;
	
	return YES;
}

- (BOOL) xadesGetSignsCount:(NSData *) xadesData
				 signsCount:(NSInteger *) signsCount
					  error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwSignsCount;
	
	*error = nil;
	
	dwError = EUXAdESGetSignsCount(
		(PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		&dwSignsCount);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signsCount)
		*signsCount = (NSInteger) dwSignsCount;
	
	return YES;
}

- (BOOL) xadesGetSignerInfo:(NSData *) xadesData
				  signIndex:(NSInteger) signIndex
				 certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
				certificate:(NSData *_Nullable *_Nullable) certificate
					  error:(NSError **) error
{
	DWORD           	dwError;
	PEU_CERT_INFO_EX	pInfoEx;
	PBYTE				pbCert;
	DWORD				dwCertLength;
	
	*error = nil;
	
	dwError = EUXAdESGetSignerInfo(
		(DWORD) signIndex,
		(PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		&pInfoEx, &pbCert, &dwCertLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (certInfoEx)
		*certInfoEx = [self makeCertificateInfoEx:pInfoEx];
	if (certificate)
		*certificate = [NSData dataWithBytes:pbCert length:dwCertLength];
	
	EUFreeCertificateInfoEx(pInfoEx);
	EUFreeMemory(pbCert);
	
	return YES;
}

- (BOOL) xadesGetSignTimeInfo:(NSData *) xadesData
					signIndex:(NSInteger) signIndex
					 timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
						error:(NSError **) error
{
	DWORD           	dwError;
	PEU_TIME_INFO		pTimeInfo;
	
	*error = nil;
	
	dwError = EUXAdESGetSignTimeInfo((DWORD) signIndex,
		(PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		&pTimeInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (timeInfo)
		*timeInfo = [self makeTimeInfo:pTimeInfo];
	
	EUFreeTimeInfo(pTimeInfo);
	
	return YES;
}

- (BOOL) xadesGetSignReferences:(NSData *) xadesData
					  signIndex:(NSInteger) signIndex
				referencesNames:(NSArray <NSString *> *_Nullable *_Nullable) referencesNames
						  error:(NSError **) error
{
	DWORD           	dwError;
	char*				pszReferences;
	
	*error = nil;
	
	dwError = EUXAdESGetSignReferences((DWORD) signIndex,
		(PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		&pszReferences);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (referencesNames)
		*referencesNames = [self makeStringsArray:pszReferences];
	
	return YES;
}

- (BOOL) xadesGetReference:(NSString *) name
				 xadesData:(NSData *) xadesData
			 referenceData:(NSData *_Nullable *_Nullable) referenceData
					 error:(NSError **) error
{
	DWORD           	dwError;
	const char*			pszName;
	PBYTE				pbData;
	DWORD				dwDataLength;
	
	*error = nil;
	
	pszName = [name cStringUsingEncoding:NSWindowsCP1251StringEncoding];
	
	dwError = EUXAdESGetReference(
		(PBYTE) xadesData.bytes, (DWORD) xadesData.length,
		(char *) pszName, &pbData, &dwDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (referenceData)
		*referenceData = [NSData dataWithBytes:pbData length:dwDataLength];
	
	EUFreeMemory(pbData);
	
	return YES;
}

- (BOOL) pdfSignData:(NSData *) pdfData
		   signLevel:(EUPAdESSignLevel) signLevel
	   signedPDFData:(NSData *_Nullable *_Nullable) signedPDFData
			   error:(NSError **) error
{
	DWORD           dwError;
	PBYTE			pbSignedPDFData;
	DWORD			dwSignedPDFDataLength;
	
	*error = nil;
	
	dwError = EUPDFSignData(
		(PBYTE) pdfData.bytes, (DWORD) pdfData.length,
		(DWORD) signLevel, &pbSignedPDFData, &dwSignedPDFDataLength);
	
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signedPDFData)
		*signedPDFData = [NSData dataWithBytes:pbSignedPDFData length:dwSignedPDFDataLength];

	EUFreeMemory(pbSignedPDFData);
	
	return YES;
}

- (BOOL) pdfVerifyData:(NSData *) signedPDFData
			 signIndex:(NSInteger) signIndex
			  signInfo:(EUSignInfo *_Nullable *_Nullable) signInfo
				 error:(NSError **) error
{
	DWORD           dwError;
	EU_SIGN_INFO	euSignInfo;
	
	*error = nil;
	
	dwError = EUPDFVerifyData((DWORD) signIndex,
		(PBYTE) signedPDFData.bytes, (DWORD) signedPDFData.length,
		&euSignInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signInfo)
		*signInfo = [self makeSignInfo:&euSignInfo];
	
	EUFreeSignInfo(&euSignInfo);
	
	return YES;
}

- (BOOL) pdfGetSignsCount:(NSData *) signedPDFData
			   signsCount:(NSInteger *) signsCount
					error:(NSError **) error
{
	DWORD           dwError;
	DWORD			dwSignsCount;
	
	*error = nil;
	
	dwError = EUPDFGetSignsCount(
		(PBYTE) signedPDFData.bytes, (DWORD) signedPDFData.length,
		&dwSignsCount);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signsCount)
		*signsCount = (NSInteger) dwSignsCount;
	
	return YES;
}

- (BOOL) pdfGetSignerInfo:(NSData *) signedPDFData
				signIndex:(NSInteger) signIndex
			   certInfoEx:(EUCertificateInfoEx *_Nullable *_Nullable) certInfoEx
			  certificate:(NSData *_Nullable *_Nullable) certificate
					error:(NSError **) error
{
	DWORD           	dwError;
	PEU_CERT_INFO_EX	pInfoEx;
	PBYTE				pbCert;
	DWORD				dwCertLength;
	
	*error = nil;
	
	dwError = EUPDFGetSignerInfo(
		(DWORD) signIndex,
		(PBYTE) signedPDFData.bytes, (DWORD) signedPDFData.length,
		&pInfoEx, &pbCert, &dwCertLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (certInfoEx)
		*certInfoEx = [self makeCertificateInfoEx:pInfoEx];
	if (certificate)
		*certificate = [NSData dataWithBytes:pbCert length:dwCertLength];
	
	EUFreeCertificateInfoEx(pInfoEx);
	EUFreeMemory(pbCert);
	
	return YES;
}

- (BOOL) pdfGetSignTimeInfo:(NSData *) signedPDFData
				  signIndex:(NSInteger) signIndex
				   timeInfo:(EUTimeInfo *_Nullable *_Nullable) timeInfo
					  error:(NSError **) error
{
	DWORD           	dwError;
	PEU_TIME_INFO		pTimeInfo;
	
	*error = nil;
	
	dwError = EUPDFGetSignTimeInfo((DWORD) signIndex,
		(PBYTE) signedPDFData.bytes, (DWORD) signedPDFData.length,
		&pTimeInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (timeInfo)
		*timeInfo = [self makeTimeInfo:pTimeInfo];
	
	EUFreeTimeInfo(pTimeInfo);
	
	return YES;
}

- (BOOL) envelopData:(NSData *) data
		toRecipients:(NSArray <NSData *>*) recipients
			signData:(BOOL) isSignData
	   envelopedData:(NSData *_Nullable *_Nullable) envelopedData
			   error:(NSError **) error
{
	return [self envelopData:data 
				toRecipients:recipients
		  contentEncAlgoType:EUContentEncAlgoGOST28147_CFB
					signData:isSignData
				  appendCert:NO
			   envelopedData:envelopedData
					   error:error];
}

- (BOOL) envelopData:(NSData *) data
		toRecipients:(NSArray <NSData *>*) recipients
  contentEncAlgoType:(EUContentEncAlgo) contentEncAlgo
			signData:(BOOL) isSignData
		  appendCert:(BOOL) isAppendCert
	   envelopedData:(NSData *_Nullable *_Nullable) envelopedData
			   error:(NSError **) error
{
	DWORD			dwError;
	DWORD			dwRecipientCerts;
	PBYTE			*ppbRecipientCerts;
	DWORD			*pdwRecipientCertsLength;
	PBYTE			pbEnvelopData;
	DWORD			dwEnvelopDataLength;

	*error = nil;

	if (![self getArrayOfByteArrays:recipients 
							  count:&dwRecipientCerts
							 arrays:&ppbRecipientCerts
					 arraysLengthes:&pdwRecipientCertsLength])
	{
		*error = [self makeError:EU_ERROR_MEMORY_ALLOCATION];

		return NO;
	}

	dwError = EUEnvelopDataToRecipientsWithSettingsEx(
		(DWORD) contentEncAlgo,
		dwRecipientCerts, ppbRecipientCerts,
		pdwRecipientCertsLength, isSignData ? TRUE : FALSE,
		(PBYTE) data.bytes, (DWORD) data.length,
		FALSE, FALSE, FALSE, isAppendCert ? TRUE : FALSE, 
		NULL, &pbEnvelopData, &dwEnvelopDataLength);
	if (dwError != EU_ERROR_NONE)
	{
		[self freeArrayOfByteArrays:dwRecipientCerts
							 arrays:ppbRecipientCerts
					 arraysLengthes:pdwRecipientCertsLength];
		
		*error = [self makeError:dwError];

		return NO;
	}

	[self freeArrayOfByteArrays:dwRecipientCerts
						 arrays:ppbRecipientCerts
				 arraysLengthes:pdwRecipientCertsLength];

	if (envelopedData)
		*envelopedData = [NSData dataWithBytes:pbEnvelopData length:dwEnvelopDataLength];

	EUFreeMemory(pbEnvelopData);

	return YES;
}

- (BOOL) developData:(NSData *) envelopedData
				data:(NSData *_Nullable *_Nullable) data
		  senderInfo:(EUSignInfo *_Nullable *_Nullable) senderInfo
			   error:(NSError **) error
{
	DWORD           dwError;
	PBYTE           pbData;
	DWORD           dwDataLength;
	EU_SIGN_INFO    euSenderInfo;

	*error = nil;

	dwError = EUDevelopData(
		NULL, (PBYTE) envelopedData.bytes, (DWORD) envelopedData.length,
		&pbData, &dwDataLength, &euSenderInfo);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	if (senderInfo)
		*senderInfo = [self makeSignInfo:&euSenderInfo];
	if (data)
		*data = [NSData dataWithBytes:pbData length:dwDataLength];

	EUFreeMemory(pbData);
	EUFreeSignInfo(&euSenderInfo);

	return YES;
}

- (BOOL) scClientIsRunning
{
    int     bRunning;
    DWORD   dwError;
    
    dwError = EUSCClientIsRunning(&bRunning);
    if (dwError != EU_ERROR_NONE)
        return NO;

    return bRunning != FALSE;
}

- (BOOL) scClientStart:(NSError **) error
{
    DWORD   dwError;
    
    *error = nil;
    
    dwError = EUSCClientStart();
    if (dwError != EU_ERROR_NONE)
    {
        *error = [self makeError:dwError];
        return NO;
    }

    return YES;
}

- (void) scClientStop
{
    EUSCClientStop();
}

- (BOOL) scClientAddGate:(EUSCClientGate *) gate
                   error:(NSError **) error
{
    const char*     pszGateName;
    unsigned short  wConnectPort;
    const char*     pszGatewayAddress;
    unsigned short  wGatewayPort;
    DWORD           dwError;
    
    *error = nil;
    
    pszGateName = [gate.name cStringUsingEncoding:NSWindowsCP1251StringEncoding];
    wConnectPort = (unsigned short) [gate.connectPort intValue];
    pszGatewayAddress = [gate.address cStringUsingEncoding:NSWindowsCP1251StringEncoding];
    wGatewayPort = (unsigned short) [gate.port intValue];
    
    dwError = EUSCClientAddGate((char *) pszGateName, wConnectPort,
        (char *) pszGatewayAddress, wGatewayPort, NULL, NULL);
    if (dwError != EU_ERROR_NONE)
    {
        *error = [self makeError:dwError];
        return NO;
    }

    return YES;
}

- (BOOL) scClientRemoveGate:(EUSCClientGate *) gate
                      error:(NSError **) error
{
    unsigned short  wConnectPort;
    DWORD           dwError;
    
    *error = nil;
    
    wConnectPort = (unsigned short) [gate.connectPort intValue];
    
    dwError = EUSCClientRemoveGate(wConnectPort);
    if (dwError != EU_ERROR_NONE)
    {
        *error = [self makeError:dwError];
        return NO;
    }
    
    return YES;
}

- (BOOL) scClientGetStatistic:(EUSCClientStatistic *_Nullable *_Nullable) statistic
						error:(NSError **) error;
{
    DWORD               dwError;
	PEU_SCC_STATISTIC   pStatistic;
	
    *error = nil;
        
    dwError = EUSCClientGetStatistic(&pStatistic);
    if (dwError != EU_ERROR_NONE)
    {
        *error = [self makeError:dwError];
        return NO;
    }
    
	if (statistic)
		*statistic = [self makeSCClientStatistic:pStatistic];

    EUSCClientFreeStatistic(pStatistic);
    
    return YES;
}

- (void) ctxFree:(EUContext *) context
{
	if (context != nil)
		EUCtxFree(context.handle);
}

- (BOOL) ctxCreate:(EUContext **) context
		     error:(NSError **) error
{
	DWORD           dwError;
	PVOID			pvContext;
	
	*error = nil;
	
	dwError = EUCtxCreate(&pvContext);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (context)
		*context = [EUContext context:pvContext];
	else
		EUCtxFree(pvContext);

	return YES;
}

- (BOOL) ctxSetParameter:(EUContext *) context
					name:(NSString *) name
				   value:(NSNumber *) value
				   error:(NSError **) error
{
	DWORD       dwError;
	const char* pszName;
	int         nValue;
	DWORD       dwValueSize;

	*error = nil;

	pszName = [name cStringUsingEncoding:NSWindowsCP1251StringEncoding];
	nValue = [value intValue];
	dwValueSize = sizeof(int);

	dwError = EUCtxSetParameter(context.handle,
		(char *) pszName, &nValue, dwValueSize);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (void) ctxFreeHash:(EUHashContext *) hashContext
{
	if (hashContext != nil)
		EUCtxFreeHash(hashContext.handle);
}

- (BOOL) ctxHashData:(EUContext *) context
			hashAlgo:(EUCtxHashAlgo) hashAlgo
		 certificate:(NSData *_Nullable) certificate
			    data:(NSData *) data
			    hash:(NSData *_Nullable *_Nullable) hash
		       error:(NSError **) error
{
	DWORD           dwError;
	PBYTE   		pbHash;
	DWORD   		dwHashLength;
	
	*error = nil;
	
    dwError = EUCtxHashData(context.handle,
        (DWORD) hashAlgo, (PBYTE) (certificate ? certificate.bytes : nil),
        (DWORD) (certificate ? certificate.length : 0),
        (PBYTE) data.bytes, (DWORD) data.length,
        &pbHash, &dwHashLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (hash)
		*hash = [NSData dataWithBytes:pbHash length:dwHashLength];

	EUCtxFreeMemory(context.handle, pbHash);

	return YES;
}

- (BOOL) ctxHashDataBegin:(EUContext *) context
				 hashAlgo:(EUCtxHashAlgo) hashAlgo
			  certificate:(NSData *_Nullable) certificate
			  hashContext:(EUHashContext *_Nullable *_Nullable) hashContext
					error:(NSError **) error
{
	DWORD			dwError;
	PVOID			pvHashContext;
	
	*error = nil;
	
    dwError = EUCtxHashDataBegin(context.handle,
        (DWORD) hashAlgo, (PBYTE) (certificate ? certificate.bytes : nil),
        (DWORD) (certificate ? certificate.length : 0),
        &pvHashContext);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (hashContext)
		*hashContext = [EUHashContext context:pvHashContext];
	else
		EUCtxFreeHash(pvHashContext);

	return YES;
}

- (BOOL) ctxHashDataContinue:(EUHashContext *) hashContext
						data:(NSData *) data
					   error:(NSError **) error
{
	DWORD           dwError;
	
	*error = nil;

	dwError = EUCtxHashDataContinue(hashContext.handle,
		(PBYTE) data.bytes, (DWORD) data.length);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}

	return YES;
}

- (BOOL) ctxHashDataEnd:(EUHashContext *) hashContext
				   hash:(NSData *_Nullable *_Nullable) hash
				  error:(NSError **) error
{
	DWORD           dwError;
	PBYTE   		pbHash;
	DWORD   		dwHashLength;
	
	*error = nil;
	
    dwError = EUCtxHashDataEnd(hashContext.handle,
        &pbHash, &dwHashLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (hash)
		*hash = [NSData dataWithBytes:pbHash length:dwHashLength];

	EUCtxFreeMemory(hashContext.handle, pbHash);

	return YES;
}

- (BOOL) ctxSignData:(EUPrivateKeyContext *) pkContext
		    signAlgo:(EUCtxSignAlgo) signAlgo
				data:(NSData *) data
			external:(BOOL) isExternal
		  appendCert:(BOOL) isAppendCert
		   signature:(NSData *_Nullable *_Nullable) signature
			   error:(NSError **) error
{
	DWORD           dwError;
	PBYTE   		pbSign;
	DWORD   		dwSignLength;
	
	*error = nil;
	
    dwError = EUCtxSignData(pkContext.handle,
        (DWORD) signAlgo,
        (PBYTE) data.bytes, (DWORD) data.length,
		isExternal ? TRUE : FALSE, 
		isAppendCert ? TRUE : FALSE,
        &pbSign, &dwSignLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signature)
		*signature = [NSData dataWithBytes:pbSign length:dwSignLength];

	EUCtxFreeMemory(pkContext.handle, pbSign);

	return YES;
}

- (BOOL) ctxGetSignValue:(EUPrivateKeyContext *) pkContext
				signAlgo:(EUCtxSignAlgo) signAlgo
					hash:(NSData *) hash
			   signValue:(NSData *_Nullable *_Nullable) signValue
				   error:(NSError **) error
{
	DWORD			dwError;
	PBYTE			pbSignValue;
	DWORD			dwSignValueLength;

	*error = nil;

	dwError = EUCtxGetSignValue(pkContext.handle,
		(DWORD) signAlgo,
		(PBYTE) hash.bytes, (DWORD) hash.length,
		&pbSignValue, &dwSignValueLength);
	if (dwError != EU_ERROR_NONE)
	{
		*error = [self makeError:dwError];
		return NO;
	}
	
	if (signValue)
		*signValue = [NSData dataWithBytes:pbSignValue length:dwSignValueLength];

	EUCtxFreeMemory(pkContext.handle, pbSignValue);

	return YES;
}

@end
