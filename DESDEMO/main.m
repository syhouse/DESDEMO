//
//  main.m
//  DESDEMO
//
//  Created by macmini on 2018/4/18.
//  Copyright © 2018年 macmini. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "DESHelper.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        NSString *encryptionString = [DESHelper encryptionDES:@"889CE963040DDB2D"];
        NSLog(@"DESHelper加密%@",encryptionString);
        
        NSLog(@"DESHelper解密%@",[DESHelper decryptionDES:encryptionString]);
    }
    return 0;
}

