/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: bn config.
 * Author: gaobo794@huawei.com
 * Create: 2020-03-04
 */

#ifndef HEADER_BN_CONF_H
# define HEADER_BN_CONF_H

/* Only one for the following should be defined */
#  if defined(__arm) || defined(__arm__)
#  define THIRTY_TWO_BIT
#  undef SIXTY_FOUR_BIT_LONG
#  undef SIXTY_FOUR_BIT
#  elif defined(__aarch64__)
#  undef SIXTY_FOUR_BIT_LONG
#  undef THIRTY_TWO_BIT
#  define SIXTY_FOUR_BIT
#  endif

#endif
