# tee_tee_os_framework Introduction<a name="ZH-CN_TOPIC_0000001148528849"></a>

-   [Introduction](#section11660541593)
-   [Directory Structure](#section161941989596)
-   [Repositories Involved](#section1371113476307)

## Introduction<a name="section11660541593"></a>

tee_tee_os_framework secondary directory code structure：

<a name="table2977131081412"></a>
<table><thead align="left"><tr id="row7977610131417"><th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.1"><p id="p18792459121314"><a name="p18792459121314"></a><a name="p18792459121314"></a>Secondary Directory</p>
</th>
<th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.2"><p id="p77921459191317"><a name="p77921459191317"></a><a name="p77921459191317"></a>Description</p>
</th>

<tr id="row6978161091412"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p64006181102"><a name="p64006181102"></a><a name="p64006181102"></a>sample</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p7456843192018"><a name="p7456843192018"></a><a name="p7456843192018"></a>sample code, contain two parts: teeloader and atf_teed</p>
</td>
</tr>

<tr id="row6978201031415"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p1978910485104"><a name="p1978910485104"></a><a name="p1978910485104"></a>test</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p1059035912204"><a name="p1059035912204"></a><a name="p1059035912204"></a>test-related code</p>
</td>
</tr>
</tbody>
</table>

The sample directory contains teeloader and atf_istrusteeed, which are only examples.
-  teeloader 

    Used to load the security image from the iTrustee TEE side to the RAM (Random Access Memory).

-  atf_teed

    As a module adapts to the ATF (Arm Trusted Firmware), provide service for switching between Trusted Execution Environment (TEE) and Rich Execution Environment (REE).

Test-related code is stored in the test directory, which is used to test the basic capabilities of the TEE trusted execution environment subsystem.

## Directory Structure<a name="section161941989596"></a>

```
base/tee/tee_os_framework
│ 
├── sample                              # sample code
│   │  
│   ├── teeloader                       # sample code for teeloader
│   │  
│   └── atf_teed                   # sample code for atf_teed
│ 
└── test                                # test-related code
```

## Repositories Involved<a name="section1371113476307"></a>

**tee subsystem**

**tee_os_framework**
