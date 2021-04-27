//
//  CoreTrust.h
//  CoreTrust
//
//  Copyright © 2017-2020 Apple Inc. All rights reserved.
//

#ifndef _CORETRUST_EVALUATE_H_
#define _CORETRUST_EVALUATE_H_

#include <stdint.h>
#include <stdbool.h>

__BEGIN_DECLS

typedef struct x509_octet_string {
    const uint8_t *data;
    size_t length;
} CTAsn1Item;

int CTParseCertificateSet(const uint8_t *der, const uint8_t *der_end,       // Input: binary representation of concatenated DER-encoded certs
                          CTAsn1Item *certStorage, size_t certStorageLen,   // Output: An array of certStorageLen CTAsn1Items that will be populated with the
                                                                            //    CTAsn1Item for each parsed cert (in the same order as input)
                          size_t *numParsedCerts);                          // Output: number of successfully parsed certs

int CTEvaluateSavageCerts(const uint8_t *certsData, size_t certsLen,
                          const uint8_t *rootKeyData, size_t rootKeyLen,
                          const uint8_t **leafKeyData, size_t *leafKeyLen,
                          bool *isProdCert);

int CTEvaluateSavageCertsWithUID(const uint8_t *certsData, size_t certsLen,
                                 const uint8_t *rootKeyData, size_t rootKeyLen,
                                 const uint8_t **leafKeyData, size_t *leafKeyLen, // Output: points to the leaf key data in the input certsData
                                 uint8_t *UIDData, size_t UIDLen,                 // Output: a pre-allocated buffer of UIDLen
                                 bool *isProdCert);

int CTEvaluateYonkersCerts(const uint8_t *certsData, size_t certsLen,
                           const uint8_t *rootKeyData, size_t rootKeyLen,
                           const uint8_t **leafKeyData, size_t *leafKeyLen, // Output: points to the leaf key data in the input certsData
                           uint8_t *UIDData, size_t UIDLen,                 // Output: a pre-allocated buffer of UIDLen
                           bool *isProdCert);

int CTEvaluateAcrt(const uint8_t *certsData, size_t certsLen,         // Input: binary representation of at most 3 concatenated certs
                                                                      //         with leaf first (root may be omitted)
                   const uint8_t **leafKeyData, size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData

int CTEvaluateUcrt(const uint8_t *certsData, size_t certsLen,         // Input: binary representation of exactly 3 concatenated
                                                                      //        DER-encoded certs, with leaf first
                   const uint8_t **leafKeyData, size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData)

int CTEvaluateUcrtTestRoot(const uint8_t *certsData, size_t certsLen,         // Input: binary representation of exactly 3 concatenated
                                                                              //        DER-encoded certs, with leaf first
                           const uint8_t *rootKeyData, size_t rootKeyLen,     // Input: Root public key, if not specified production root will be used
                           const uint8_t **leafKeyData, size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData)

int CTEvaluateBAASystem(const uint8_t *certsData, size_t certsLen,         // Input: binary representation of exactly 3 concatenated
                                                                           //        DER-encoded certs, with leaf first
                        const uint8_t **leafKeyData, size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData

typedef struct baa_identity {
    uint32_t chipId;
    uint64_t ecid;
    bool productionStatus;
    bool securityMode;
    uint8_t securityDomain;
    CTAsn1Item img4;
} CTBAAIdentity;

int CTEvaluateBAASystemWithId(const uint8_t *certsData, size_t certsLen,        // Input: binary representation of exactly 3 concatenated
                                                                                //        DER-encoded certs, with leaf first
                              const uint8_t **leafKeyData, size_t *leafKeyLen,  // Output: points to the leaf key data in the input certsData
                              CTBAAIdentity *identity);                         // Output from identity field in leaf certificate

int CTEvaluateBAASystemTestRoot(const uint8_t *certsData, size_t certsLen,      // Input: binary representation of exactly 3 concatenated
                                                                                //        DER-encoded certs, with leaf first
                                const uint8_t *rootKeyData, size_t rootKeyLen,  // Input: Root public key, if not specified production root will be used
                                const uint8_t **leafKeyData, size_t *leafKeyLen,// Output: points to the leaf key data in the input certsData
                                CTBAAIdentity *identity);                       // Output from identity field in leaf certificate

int CTEvaluateBAAUser(const uint8_t *certsData, size_t certsLen,        // Input: binary representation of exactly 3 concatenated
                                                                        //        DER-encoded certs, with leaf first
                      const uint8_t **leafKeyData, size_t *leafKeyLen,  // Output: points to the leaf key data in the input certsData
                      CTBAAIdentity *identity);                         // Output from identity field in leaf certificate

int CTEvaluateBAAUserTestRoot(const uint8_t *certsData, size_t certsLen,        // Input: binary representation of exactly 3 concatenated
                                                                                //        DER-encoded certs, with leaf first
                              const uint8_t *rootKeyData, size_t rootKeyLen,    // Input: Root public key, if not specified production root will be used
                              const uint8_t **leafKeyData, size_t *leafKeyLen,  // Output: points to the leaf key data in the input certsData
                              CTBAAIdentity *identity);                         // Output from identity field in leaf certificate

int CTEvaluateSatori(const uint8_t *certsData, size_t certsLen,         // Input: binary (DER) representation of 3 concatenated certs
                                                                        //        with leaf first
                     bool allowTestRoot,                                // Input: whether to allow the Test Apple Roots
                     const uint8_t **leafKeyData, size_t *leafKeyLen);  // Output: points to the leaf key data in the input certsData

int CTEvaluatePragueSignatureCMS(const uint8_t *cmsData, size_t cmsLen,                 // Input: CMS signature blob
                                 const uint8_t *detachedData, size_t detachedDataLen,   // Input: data signed by CMS blob
                                 bool allowTestRoot,                                    // Input: permit use of test hierarchy
                                 const uint8_t **leafKeyData, size_t *leafKeyLen);      // Output: points to leaf key data in input cmsData

int CTEvaluateKDLSignatureCMS(const uint8_t *cmsData, size_t cmsLen,                    // Input: CMS signature blob
                              const uint8_t *detachedData, size_t detachedDataLen,      // Input: data signed by CMS blob
                              bool allowTestRoot,                                       // Input: permit use of test hierarchy
                              const uint8_t **leafKeyData, size_t *leafKeyLen);         // Output: points to leaf key data in input cmsData

typedef uint64_t CoreTrustPolicyFlags;
enum {
    CORETRUST_POLICY_BASIC =                0,
    CORETRUST_POLICY_SAVAGE_DEV =           1 << 0,
    CORETRUST_POLICY_SAVAGE_PROD =          1 << 1,
    CORETRUST_POLICY_MFI_AUTHV3 =           1 << 2,
    CORETRUST_POLICY_MAC_PLATFORM =         1 << 3,
    CORETRUST_POLICY_MAC_DEVELOPER =        1 << 4,
    CORETRUST_POLICY_DEVELOPER_ID =         1 << 5,
    CORETRUST_POLICY_MAC_APP_STORE =        1 << 6,
    CORETRUST_POLICY_IPHONE_DEVELOPER =     1 << 7,
    CORETRUST_POLICY_IPHONE_APP_PROD =      1 << 8,
    CORETRUST_POLICY_IPHONE_APP_DEV =       1 << 9,
    CORETRUST_POLICY_IPHONE_VPN_PROD =      1 << 10,
    CORETRUST_POLICY_IPHONE_VPN_DEV =       1 << 11,
    CORETRUST_POLICY_TVOS_APP_PROD =        1 << 12,
    CORETRUST_POLICY_TVOS_APP_DEV =         1 << 13,
    CORETRUST_POLICY_TEST_FLIGHT_PROD =     1 << 14,
    CORETRUST_POLICY_TEST_FLIGHT_DEV =      1 << 15,
    CORETRUST_POLICY_IPHONE_DISTRIBUTION =  1 << 16,
    CORETRUST_POLICY_MAC_SUBMISSION =       1 << 17,
    CORETRUST_POLICY_YONKERS_DEV =          1 << 18,
    CORETRUST_POLICY_YONKERS_PROD =         1 << 19,
    CORETRUST_POLICY_MAC_PLATFORM_G2 =      1 << 20,
    CORETRUST_POLICY_ACRT =                 1 << 21,
    CORETRUST_POLICY_SATORI =               1 << 22,
    CORETRUST_POLICY_BAA =                  1 << 23,
    CORETRUST_POLICY_UCRT =                 1 << 24,
    CORETRUST_POLICY_PRAGUE =               1 << 25,
    CORETRUST_POLICY_KDL =                  1 << 26,
    CORETRUST_POLICY_MFI_AUTHV2 =           1 << 27,
    CORETRUST_POLICY_MFI_SW_AUTH_PROD =     1 << 28,
    CORETRUST_POLICY_MFI_SW_AUTH_DEV =      1 << 29,
    CORETRUST_POLICY_COMPONENT =            1 << 30,
    CORETRUST_POLICY_IMG4 =                 1ULL << 31,
    CORETRUST_POLICY_SERVER_AUTH =          1ULL << 32,
    CORETRUST_POLICY_SERVER_AUTH_STRING =   1ULL << 33,
};

typedef uint32_t CoreTrustDigestType;
enum {
    CORETRUST_DIGEST_TYPE_SHA1 = 1,
    CORETRUST_DIGEST_TYPE_SHA224 = 2,
    CORETRUST_DIGEST_TYPE_SHA256 = 4,
    CORETRUST_DIGEST_TYPE_SHA384 = 8,
    CORETRUST_DIGEST_TYPE_SHA512 = 16
};

int CTEvaluateAMFICodeSignatureCMS(const uint8_t *cmsData, size_t cmsLen,                   // Input: CMS blob
                                   const uint8_t *detachedData, size_t detachedDataLen,     // Input: data signed by CMS blob
                                   bool allow_test_hierarchy,                               // Input: permit use of test hierarchy
                                   const uint8_t **leafCert, size_t *leafCertLen,           // Output: signing certificate
                                   CoreTrustPolicyFlags *policyFlags,                       // Output: policy met by signing certificate
                                   CoreTrustDigestType *cmsDigestType,                      // Output: digest used to sign the CMS blob
                                   CoreTrustDigestType *hashAgilityDigestType,              // Output: highest stregth digest type
                                                                                            //          from hash agility attribute
                                   const uint8_t **digestData, size_t *digestLen);          // Output: pointer to hash agility value
                                                                                            //          in CMS blob (with digest type above)
/* Returns non-zero if there's a standards-based problem with the CMS or certificates.
 * Policy matching of the certificates is only reflected in the policyFlags output. Namely, if the only problem is that
 * the certificates don't match a policy, the returned integer will be 0 (success) and the policyFlags will be 0 (no matching policies).
 * Some notes about hash agility outputs:
 *  - hashAgilityDigestType is only non-zero for HashAgilityV2
 *  - If hashAgilityDigestType is non-zero, digestData/Len provides the digest value
 *  - If hashAgilityDigestType is zero, digestData/Len provides the content of the HashAgilityV1 attribute (if present)
 *  - If neither HashAgilityV1 nor HashAgilityV2 attributes are found, these outputs will all be NULL.
 */

int CTParseAccessoryCerts(const uint8_t *certsData, size_t certsLen,                    // Input: CMS or binary representation of DER-encoded certs
                                  const uint8_t **leafCertData, size_t *leafCertLen,    // Output: points to leaf cert data in input certsData
                                  const uint8_t **subCACertData, size_t *subCACertLen,  // Output: points to subCA cert data (1st of 2) in input certsData, if present. Is set to NULL if only one cert present in input.
                                  CoreTrustPolicyFlags *flags);                         // Output: policy flags set by this leaf


int CTEvaluateAccessoryCert(const uint8_t *leafCertData, size_t leafCertLen,            // Input: binary representation of DER-encoded leaf cert
                            const uint8_t *subCACertData, size_t subCACertLen,          // Input: (optional) binary representation of DER-encoded subCA cert
                            const uint8_t *anchorCertData, size_t anchorCertLen,        // Input: binary representation of DER-encoded anchor cert
                            CoreTrustPolicyFlags policy,                                // Input: policy to use when evaluating chain
                            const uint8_t **leafKeyData, size_t *leafKeyLen,            // Output: points to the leaf key data in the input leafCertData
                            const uint8_t **extensionValueData, size_t *extensionValueLen); // Output: points to the extension value in the input leafCertData
/* Which extension value is returned is based on which policy the cert was verified against:
 *  - For MFI AuthV3, this is the value of the extension with OID 1.2.840.113635.100.6.36
 *  - For SW Auth, this is the value of the extension with OID 1.2.840.113635.100.6.59.1 (GeneralCapabilities extension)
 *  - For Component certs, this si the value of the extension with OID 1.2.840.113635.100.11.1 (Component Type)
 *
 * The following CoreTrustPolicyFlags are accepted:
 *  - CORETRUST_POLICY_BASIC
 *  - CORETRUST_POLICY_MFI_AUTHV2
 *  - CORETRUST_POLICY_MFI_AUTHV3
 *  - CORETRUST_POLICY_MFI_SW_AUTH_DEV
 *  - CORETRUST_POLICY_MFI_SW_AUTH_PROD
 *  - CORETRUST_POLICY_COMPONENT
 */

int CTEvaluateAppleSSL(const uint8_t *certsData, size_t certsLen,           // Input: binary representation of up to 3 concatenated
                                                                            //        DER-encoded certificates, with leaf first
                       const uint8_t *hostnameData, size_t hostnameLen,     // Input: The hostname of the TLS server being connected to
                       uint64_t leafMarker,                                 // Input: The last decimal of the marker OID for this project
                                                                            //        (e.g. 32 for 1.2.840.113635.100.6.27.32
                       bool allowTestRoots);                                // Input: permit use of test hierarchy

int CTEvaluateAppleSSLWithOptionalTemporalCheck(const uint8_t *certsData, size_t certsLen,
                                                 const uint8_t *hostnameData, size_t hostnameLen,
                                                 uint64_t leafMarker,
                                                 bool allowTestRoots,
                                                 bool checkTemporalValidity);

__END_DECLS

#endif /* _CORETRUST_EVALUATE_H_ */
