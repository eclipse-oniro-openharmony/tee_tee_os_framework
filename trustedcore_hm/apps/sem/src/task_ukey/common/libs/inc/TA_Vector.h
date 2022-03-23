#ifndef TA_VECTOR_H
#define TA_VECTOR_H

#include "TA_Parcel.h"
#include "libhwsecurec/securec.h"

/* Usage example
 *
 *    typedef struct {
 *        int a;
 *        char b[10];
 *        double c;
 *    } TestSt;
 *
 *    DECLARE_TA_VECTOR(TestVec, TestSt)
 *    IMPLEMENT_TA_VECTOR(TestVec, TestSt, 10)
 *
 *    void test()
 *    {
 *        int i = 0;
 *        TestVec tv = CREATE_TA_VECTOR(TestVec);
 *        for(i = 0; i < 10; ++i)
 *        {
 *            TestSt ts;
 *            ts.a = i;
 *            ts.c = 0.7*i;
 *            tv.push_back(&tv, ts);
 *        }
 *
 *        for(i = 0; i < tv.size(&tv); ++i)
 *        {
 *            int a = tv.get(&tv, i).a;
 *        }
 *
 *        while(tv.pop_front(&tv, &ts))
 *        {
 *            int a = ts.a;
 *        }
 *
 *        DESTROY_TA_VECTOR(TestVec, &tv);
 *	}
 */

/*
 * Use DECLARE_TA_VECTOR to declare the vector in the head/src file.
 * @para _classname:        the name of the vector-class/vector-struct
 * @para _element:          the type of the vector element
 * @for example:
 * DECLARE_C_VECTOR(IntVec, int)
 */
#define DECLARE_TA_VECTOR(_classname, _element)                                 \
typedef struct v_##_classname{                                                  \
    _element* (*push_back) (struct v_##_classname*, _element*);                  \
    bool (*pop_front) (struct v_##_classname*, _element*);                      \
    bool (*erase_element) (struct v_##_classname*, _element*,uint32_t index);       \
    uint32_t (*size) (const struct v_##_classname*);                            \
    _element (*get) (const struct v_##_classname*, uint32_t index);             \
    _element* (*getp) (const struct v_##_classname*, uint32_t index);           \
    ta_parcel_t parcel;                                                         \
} _classname;                                                                   \
                                                                                \
_element* v_push_back_##_element(_classname* obj, _element *e);                  \
bool v_pop_front_##_element(_classname* obj, _element* e);                      \
uint32_t v_size_##_element(const _classname* obj);                              \
_element v_get_##_element(const _classname* obj, uint32_t index);               \
_element* v_getp_##_element(const _classname* obj, uint32_t index);             \
_classname create_##_classname();                                               \
void destroy_##_classname(_classname* obj);

/*
 * Use IMPLEMENT_TA_VECTOR to implement the vector in the source file.
 * @para _classname:        the name of the vector-class/vector-struct
 * @para _element:          the type of the vector element
 * @para _alloc_count:      the minimum alloc count
 * @for example:
 * IMPLEMENT_TA_VECTOR(IntVec, int)
 */
#define IMPLEMENT_TA_VECTOR(_classname, _element, _alloc_count)                 \
_element* v_push_back_##_element(_classname* obj, _element *e) {                 \
    if(NULL == obj || NULL == e)                                                 \
    {                                                                           \
        return NULL;                                                            \
    }                                                                           \
                                                                                \
    if(parcel_write(&obj->parcel, e, sizeof(_element)))                        \
    {                                                                           \
        int size = obj->size(obj);                                              \
        return obj->getp(obj, size-1);                                          \
    }                                                                           \
    else                                                                        \
    {                                                                           \
        return NULL;                                                            \
    }                                                                           \
}                                                                               \
                                                                                \
bool v_pop_front_##_element(_classname* obj, _element* e) {                     \
        if(NULL == obj || NULL == e)                                            \
        {                                                                       \
            return false;                                                       \
        }                                                                       \
        if(obj->size(obj) > 0)                                                  \
        {                                                                       \
            return parcel_read(&obj->parcel, e, sizeof(_element));              \
        }                                                                       \
        else                                                                    \
        {                                                                       \
            return false;                                                       \
        }                                                                       \
}                                                                               \
bool v_erase_##_element(_classname* obj, _element* e,uint32_t index) { \
        if(NULL == obj || NULL == e || index + 1 > obj->size(obj))  \
        { \
            return false; \
        } \
        if(obj->size(obj) > 0) \
        { \
            return parcel_erase_block(&obj->parcel,index*sizeof(_element), sizeof(_element),e);\
        } \
        else \
        { \
            return false; \
        } \
} \
uint32_t v_size_##_element(const _classname* obj)                               \
{                                                                               \
    if(NULL == obj)                                                             \
    {                                                                           \
        return 0;                                                               \
    }                                                                           \
    return get_parcel_data_size(&obj->parcel) / sizeof(_element);               \
}                                                                               \
                                                                                \
_element v_get_##_element(const _classname* obj, uint32_t index)                \
{                                                                                    \
    _element e;                                                                 \
    (void)memset_s(&e, sizeof(e), 0, sizeof(e));                                \
    if(NULL != obj)                                                             \
    {                                                                                 \
        if(index < obj->size(obj))                                           \
        {                                                                               \
            if(get_parcel_data(&obj->parcel))                              \
              return *((_element*)(get_parcel_data(&obj->parcel))+index); \
            else                                                                           \
              return e;                                                                    \
        }                                                                                         \
    }                                                                                            \
    /* error usage!! should never to here */                                    \
    (void)memset_s(&e, sizeof(e), 0, sizeof(e));                                \
    return e;                                                                   \
}                                                                               \
                                                                                \
_element* v_getp_##_element(const _classname* obj, uint32_t index)              \
{                                                                               \
    if(NULL != obj)                                                             \
    {                                                                           \
        if(index < obj->size(obj))                                              \
        {                       \
            if(get_parcel_data(&obj->parcel))               \
            return ((_element*)(get_parcel_data(&obj->parcel))+index);          \
            else \
                return NULL;                                              \
        }                                                                       \
    }                                                                           \
    return NULL;                                                                \
}                                                                               \
                                                                                \
_classname create_##_classname()                                                \
{                                                                               \
    _classname obj;                                                             \
    obj.push_back = v_push_back_##_element;                                     \
    obj.pop_front = v_pop_front_##_element;                                     \
    obj.erase_element = v_erase_##_element;                                   \
    obj.size = v_size_##_element;                                               \
    obj.get = v_get_##_element;                                                 \
    obj.getp = v_getp_##_element;                                               \
    obj.parcel = create_parcel(0, sizeof(_element)*_alloc_count);               \
    return obj;                                                                 \
}                                                                               \
                                                                                \
void destroy_##_classname(_classname* obj)                                      \
{                                                                               \
    if(NULL != obj)                                                             \
    {                                                                           \
        delete_parcel(&obj->parcel);                                            \
    }                                                                           \
}

/*
 * Use these two macro to create and destroy vector
 */
#define CREATE_TA_VECTOR(_classname) create_##_classname();
#define DESTROY_TA_VECTOR(_classname, _obj) destroy_##_classname(_obj);
#define CLEAR_TA_VECTOR(_classname, _obj) destroy_##_classname(_obj);

#define FOR_EACH_TA_VECTOR(vec, index, iter) for(index = 0; index < (vec).size(&(vec)) && (iter = (vec).getp(&(vec), index)); ++index)

#define TA_VECTOR_PUSHBACK(_obj, _element) (_obj)->push_back((_obj), (_element))
#define TA_VECTOR_POPFRONT(_obj, _element) (_obj)->pop_front((_obj), (_element))
#define TA_VECTOR_POPELEMENT(_obj, _element,_index) (_obj)->erase_element((_obj), (_element), (_index))
#define TA_VECTOR_SIZE(_obj) (_obj)->size(_obj)
#define TA_VECTOR_GET(_obj, _index) (_obj)->get((_obj), (_index))
#define TA_VECTOR_GETP(_obj, _index) (_obj)->getp((_obj), (_index))

#endif
