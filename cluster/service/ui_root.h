#ifndef VBC_UI_ROOT_H
#define VBC_UI_ROOT_H
/* Strong Screen/root references stay alive through the attachment probe. */
struct VbcUiSharedNode {
    void *object,*owner;
    ~VbcUiSharedNode() {
    }
};
struct VbcUiRoot {
    using Resolve=void *(*)(const char *,const char *);
    VbcUiSharedNode (*screen)() {
    };
    VbcUiSharedNode (*root)(const void *) {
    };
    bool (*attached)(const void *) {
    };
    void (*release)(void *) {
    };
    bool ready(Resolve resolve) {
        if(!screen) {
            screen=(decltype(screen))resolve(nullptr,"_Z20getApplicationScreenv");
        }
        if(!root) {
            root=(decltype(root))resolve("/lib64/libkzcoreui.so","_ZNK5kanzi6Screen7getRootEv");
        }
        if(!attached) {
            attached=(decltype(attached))resolve("/lib64/libkzcoreui.so","_ZNK5kanzi4Node10isAttachedEv");
        }
        if(!release) {
            release=(decltype(release))resolve(nullptr,"_ZNSt16_Sp_counted_baseILN9__gnu_cxx12_Lock_policyE2EE10_M_releaseEv");
        }
        if(!screen||!root||!attached||!release) {
            return false;
        }
        VbcUiSharedNode current=screen();
        VbcUiSharedNode node=current.object&&current.owner?root(current.object):VbcUiSharedNode{};
        bool result=node.object&&node.owner&&attached(node.object);
        if(node.owner) {
            release(node.owner);
        }
        if(current.owner) {
            release(current.owner);
        }
        return result;
    }
};
#endif
