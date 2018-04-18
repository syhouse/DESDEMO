//
//  DESHelper.m
//  MachineTool
//
//  Created by macmini on 2018/4/9.
//  Copyright © 2018年 macmini. All rights reserved.
//

#import "DESHelper.h"
#import "GTMBase64.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

//static const Byte iv[] = { 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32};
static const Byte iv[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };


@implementation DESHelper
+ (NSString *)encryptionDES8:(NSString *)encryptString{
    NSString *ciphertext = nil;
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    
    NSData *testData = [encryptString dataUsingEncoding: NSUTF8StringEncoding];

    //DES补齐方式  不足8个字节补足8个字节
    int r = 8 - (int)[testData length]%8;
    

    NSUInteger dataLen = [testData length];
    NSUInteger bLen = dataLen + r;
    Byte *byteData = (Byte*)malloc(bLen);
    memcpy(byteData, [testData bytes], bLen);

    for(int i = 0 ; i < r ; i++){
        byteData[dataLen + i] = 0;
    }

    testData = [NSData dataWithBytes:byteData length:[encryptString length] + r];
    CCCryptorRef cryptor = NULL;
    
//    static const void * ivv = [@"98765432" UTF8String];
//    NSString *someString = @"98765432";
//    uint8_t test[100];
//    memcpy(test, [someString UTF8String], [someString length]+1);
//    Byte iv[] = { 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32};
//    int a = '0x12';
//    int b = '4';
//    int c = 'V';
//    int d = 'x';
//    int e = '\x90';
//    int f = '\xab';
//    int g = '\xcd';
//    int h = '\xef';
    
    CCCryptorStatus cryptStatus = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCBC, kCCAlgorithmDES, ccNoPadding, iv, [key UTF8String], kCCKeySizeDES, NULL, 0, 0, kCCModeOptionCTR_LE, &cryptor);
    
    if (cryptStatus != kCCSuccess) {
        NSLog(@"CCCryptorCreateWithMode Failed to create cryptor: %d", cryptStatus);
        exit(0);
    }
    NSMutableData *cipherData = [NSMutableData data];
    size_t outLength = 0;
    size_t bufferLength = CCCryptorGetOutputLength(cryptor, testData.length, true);
    NSMutableData *bufferData = [NSMutableData dataWithLength:bufferLength];
    cryptStatus = CCCryptorUpdate(cryptor,
                                  [testData bytes],
                                  [testData length],
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
        NSLog(@"CCCryptorUpdate Failed to create cryptor: %d", cryptStatus);
    }
    
    if (cryptStatus == kCCSuccess){
        cryptStatus = CCCryptorRelease(cryptor);
    }
    else{
        NSLog(@"CCCryptorRelease Failed to create cryptor: %d", cryptStatus);
    }
    
    if (cryptStatus == kCCSuccess) {
        
        ciphertext = [[NSString alloc] initWithData:[GTMBase64 encodeData:cipherData] encoding:NSUTF8StringEncoding];
    }
    return ciphertext;
}

+ (NSString *)decryptionDES8:(NSString *)decryptString{
    NSString *plaintext = nil;
    NSData *cipherdata = [GTMBase64 decodeString:decryptString];
    unsigned char buffer[1024];
    memset(buffer, 0, sizeof(char));
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmDES,
                                          kCCOptionPKCS7Padding,
                                          [key UTF8String], kCCKeySizeDES,
                                          iv,
                                          [cipherdata bytes], [cipherdata length],
                                          buffer, 1024,
                                          &numBytesDecrypted);
    if(cryptStatus == kCCSuccess)
    {
        NSData *plaindata = [NSData dataWithBytes:buffer length:(NSUInteger)numBytesDecrypted];
        plaintext = [[NSString alloc]initWithData:plaindata encoding:NSUTF8StringEncoding];
        
        //移除自己增补的0
        plaintext = [plaintext stringByReplacingOccurrencesOfString:@"\0" withString:@""];
    }
    return plaintext;
}
@end
