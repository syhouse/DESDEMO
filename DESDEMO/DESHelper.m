//
//  DESHelper.m
//  DESDEMO
//
//  Created by macmini on 2018/4/9.
//  Copyright © 2018年 macmini. All rights reserved.
//

#import "DESHelper.h"
#import "GTMBase64.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
static const Byte iv[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};

@implementation DESHelper
+ (NSString *)encryptionDES:(NSString *)encryptString{
    NSString *ciphertext = nil;
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    
    NSData *encryptData = [encryptString dataUsingEncoding: NSUTF8StringEncoding];
    //需要补0字节的数量
    int r = 8 - (int)[encryptData length]%8;
    NSUInteger dataLen = [encryptData length];
    NSUInteger bLen = dataLen + r;
    Byte *byteData = (Byte*)malloc(bLen);
    memcpy(byteData, [encryptData bytes], bLen);
    for(int i = 0 ; i < r ; i++){
        byteData[dataLen + i] = 0;
    }
    
    //补齐后的解密data
    encryptData = [NSData dataWithBytes:byteData length:[encryptString length] + r];
    CCCryptorRef cryptor = NULL;
    
    CCCryptorStatus cryptStatus = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCBC, kCCAlgorithmDES, ccNoPadding, iv, [key UTF8String], kCCKeySizeDES, NULL, 0, 0, kCCModeOptionCTR_LE, &cryptor);
    
    if (cryptStatus != kCCSuccess) {
        NSLog(@"CCCryptorCreateWithMode Failed to create cryptor: %d", cryptStatus);
    }
    NSMutableData *cipherData = [NSMutableData data];
    size_t outLength = 0;
    size_t bufferLength = CCCryptorGetOutputLength(cryptor, encryptData.length, true);
    NSMutableData *bufferData = [NSMutableData dataWithLength:bufferLength];
    cryptStatus = CCCryptorUpdate(cryptor,
                                  [encryptData bytes],
                                  [encryptData length],
                                  [bufferData mutableBytes],
                                  [bufferData length],
                                  &outLength);
   
    [cipherData appendBytes:bufferData.bytes length:outLength];
    if (cryptStatus == kCCSuccess){
        cryptStatus = CCCryptorFinal(cryptor,
                                     [bufferData mutableBytes],
                                     [bufferData length],
                                     &outLength);
    }
    else{
        NSLog(@"CCCryptorUpdate Failed to update cryptor: %d", cryptStatus);
    }
    
    if (cryptStatus == kCCSuccess){
        cryptStatus = CCCryptorRelease(cryptor);
    }
    else{
        NSLog(@"CCCryptorRelease Failed to final cryptor: %d", cryptStatus);
    }
    
    if (cryptStatus == kCCSuccess) {
        
        ciphertext = [[NSString alloc] initWithData:[GTMBase64 encodeData:cipherData] encoding:NSUTF8StringEncoding];
    }
    return ciphertext;
}

+ (NSString *)decryptionDES:(NSString *)decryptString{
    NSData* cipherData = [GTMBase64 decodeString:decryptString];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String],
                                          kCCKeySizeDES,
                                          iv,
                                          [cipherData bytes],
                                          [cipherData length],
                                          buffer,
                                          1024,
                                          &numBytesDecrypted);
    NSString* plainText = nil;
    if (cryptStatus == kCCSuccess) {
        NSData* data = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        plainText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
        //移除自己添加的0字节
        plainText = [plainText stringByReplacingOccurrencesOfString:@"\0" withString:@""];
    }
    return plainText;
}
@end
