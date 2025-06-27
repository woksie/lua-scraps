script_name('passenger driver')
script_author('woksie')

local samem	= require 'SAMemory'
local ffi	= require 'ffi'

samem.require 'CAutomobile'

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

local bActive = false

function main()
    sampRegisterChatCommand("pdrive", function()
        bActive = not bActive
        printStringNow("drive as passenger " .. (bActive and "~g~~h~~h~ON" or "~r~~h~~h~OFF"), 800)
    end)

    vehicleProcessControlHook = hook.new(
        "void (__thiscall *)(CAutomobile*)",
        vehicleProcessControlHook,
        0x6B1880  -- CAutomobile::ProcessControl
    )
end

function vehicleProcessControlHook(pAutomobile)
    local hVehicle = getVehiclePointerHandle(tonumber(ffi.cast("uintptr_t", pAutomobile)))
    local pPlayer = samem.player_ped[0]

    if bActive and isCharInCar(playerPed, hVehicle) and pAutomobile.pDriver ~= pPlayer then
        local pDriver = pAutomobile.pDriver
        pAutomobile.pDriver = pPlayer
        vehicleProcessControlHook(pAutomobile)
        pAutomobile.nStatus = 0 -- STATUS_PLAYER eEntityStatus 
        pAutomobile.pDriver = pDriver
    else
        vehicleProcessControlHook(pAutomobile)
    end
end

