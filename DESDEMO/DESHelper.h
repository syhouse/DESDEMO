//
//  DESHelper.h
//  DESDEMO
//
//  Created by macmini on 2018/4/9.
//  Copyright © 2018年 macmini. All rights reserved.
//

#import <Foundation/Foundation.h>

static const NSString *key = @"OT001111";

@interface DESHelper : NSObject
+ (NSString *)encryptionDES:(NSString *)encryptString;

+ (NSString *)decryptionDES:(NSString *)decryptString;
@end
