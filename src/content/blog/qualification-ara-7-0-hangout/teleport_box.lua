local TeleportService = game:GetService("TeleportService")
local Players = game:GetService("Players")

local TargetPlaceID = 97219492225892 -- Lobby ARA
local part = script.Parent
local debounce = {}

part.Touched:Connect(function(hit)
    local player = Players:GetPlayerFromCharacter(hit.Parent)
    if not player then return end

    if debounce[player] then return end
    debounce[player] = true

    local opt = Instance.new("TeleportOptions")
    opt:SetTeleportData({
        Score = 1000000001,
        -- Must be > 1e9
    })

    local ok, err = pcall(function()
        TeleportService:TeleportAsync(TargetPlaceID, {player}, opt)
    end)

    if not ok then
        warn("Teleport failed:", err)
    end

    task.delay(2, function()
        debounce[player] = nil
    end)
end)

Players.PlayerRemoving:Connect(function(p)
    debounce[p] = nil
end)
