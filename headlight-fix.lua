--[[
	GTA SA has a bug in CVehicle::DoHeadLightBeam function - it incorrectly
	restores render states after drawing headlight beams. Specifically 
	rwRENDERSTATECULLMODE gets restored to "front" instead of "none", causing 
	incorrect rendering of polygon back faces.
	
	SilentPatch wraps the function - saves current render states 
	before call, lets function execute, then properly restores all render states.
	
	This script uses simpler approach - hooks CVehicle::DoHeadLightBeam at 0x6E0E20,
	calls original function (which corrupts render states), then forcibly sets 
	rwRENDERSTATECULLMODE to value 1 (none backface culling mode).
	
	https://github.com/multitheftauto/mtasa-blue/issues/2936
	https://cookieplmonster.github.io/2019/02/03/clever-bug-exploitation-backface-culling/
--]]

script_name('DoHeadLightBeam culling fix')
script_description('patches CVehicle::DoHeadLightBeam render state corruption')
script_author('woksie')

local ffi = require 'ffi'

ffi.cdef[[
typedef unsigned int RwUInt32;
typedef void (*RwRenderStateSetFunction)(RwUInt32 state, void* value);

struct RwDevice {
    float gammaCorrection;
    void* fpSystem;
    float zBufferNear;
    float zBufferFar;
    RwRenderStateSetFunction fpRenderStateSet;
};

struct RwGlobals {
    void* curCamera;
    void* curWorld;
    unsigned short renderFrame;
    unsigned short lightFrame;
    unsigned short pad[2];
    struct RwDevice dOpenDevice;
    void* stdFunc;
    void* dirtyFrameList;
    void* stringFuncs;
    void* memoryFuncs;
    void* memoryAlloc;
    void* memoryFree;
    void* metrics;
    int engineStatus;
    RwUInt32 resArenaInitSize;
};

int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
]]

local RwEngineInstance = ffi.cast("struct RwGlobals**", 0xC97B24)[0]
local rwRENDERSTATECULLMODE = 20

--HOOKS
local hook = {hooks = {}}
addEventHandler('onScriptTerminate', function(scr)
    if scr == script.this then
        for i, hook in ipairs(hook.hooks) do
            if hook.status then
                hook.stop()
            end
        end
    end
end)
ffi.cdef [[
    int VirtualProtect(void* lpAddress, unsigned long dwSize, unsigned long flNewProtect, unsigned long* lpflOldProtect);
]]
function hook.new(cast, callback, hook_addr, size)
    jit.off(callback, true) --off jit compilation | thx FYP
    local size = size or 5
    local new_hook = {}
    local detour_addr = tonumber(ffi.cast('intptr_t', ffi.cast('void*', ffi.cast(cast, callback))))
    local void_addr = ffi.cast('void*', hook_addr)
    local old_prot = ffi.new('unsigned long[1]')
    local org_bytes = ffi.new('uint8_t[?]', size)
    ffi.copy(org_bytes, void_addr, size)
    local hook_bytes = ffi.new('uint8_t[?]', size, 0x90)
    hook_bytes[0] = 0xE9
    ffi.cast('uint32_t*', hook_bytes + 1)[0] = detour_addr - hook_addr - 5
    new_hook.call = ffi.cast(cast, hook_addr)
    new_hook.status = false
    local function set_status(bool)
        new_hook.status = bool
        ffi.C.VirtualProtect(void_addr, size, 0x40, old_prot)
        ffi.copy(void_addr, bool and hook_bytes or org_bytes, size)
        ffi.C.VirtualProtect(void_addr, size, old_prot[0], old_prot)
    end
    new_hook.stop = function() set_status(false) end
    new_hook.start = function() set_status(true) end
    new_hook.start()
    table.insert(hook.hooks, new_hook)
    return setmetatable(new_hook, {
        __call = function(self, ...)
            self.stop()
            local res = self.call(...)
            self.start()
            return res
        end
    })
end
--HOOKS

function main()
    doHeadlightBeamHook = hook.new(
        "void(__thiscall*)(void* this, int, void*, char)",
        doHeadlightBeamHook,
        0x6E0E20 -- CVehicle::DoHeadLightBeam
    )
end

function doHeadlightBeamHook(this, dummyId, matrixPtr, arg2)
    doHeadlightBeamHook(this, dummyId, matrixPtr, arg2)
    RwEngineInstance.dOpenDevice.fpRenderStateSet(rwRENDERSTATECULLMODE, ffi.cast("void*", 1))
end