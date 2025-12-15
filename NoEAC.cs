//#define DEV
using System;
using System.Collections.Generic;
using System.Reflection;
using System.Reflection.Emit;
using HarmonyLib;
using JetBrains.Annotations;
using Network;
using Oxide.Core;
using Oxide.Core.Plugins;
using Oxide.Plugins;

namespace Oxide.Plugins;

[Info("No EAC", "Patrette", "1.3.0")]
[Description("Allows certain users to bypass EAC")]
public class NoEAC : RustPlugin
{
	public const int encryption_override = 1; // only change if you know what you're doing

	public const string PermID = "noeac.use";

	public static NoEAC self;

	private void Init()
	{
		self = this;
	}

	private void Unload()
	{
		self = null;
	}

	private void OnServerInitialized()
	{
		permission.RegisterPermission(PermID, this);
	}

	private static bool CanBypass(Connection connection)
	{
		return self != null && self.permission.UserHasPermission(connection.userid.ToString(), PermID);
	}

	// Returns the encryption level for a user
	// 2: EAC Black magic
	// 1: XOR using the network protocol uint and a constant 256 byte salt (also bad idea)
	// 0: Nothing (bad idea)
	private static int UserEncryptionOverride(Network.Server sv, Connection connection)
	{
		try
		{
			if (CanBypass(connection))
			{
				Interface.Oxide.LogWarning($"Allowing user {connection} to connect without EAC");
				return encryption_override;
			}
		}
		catch (Exception e)
		{
			Interface.Oxide.LogWarning($"Phase 2 failed for {connection.userid}", e);
		}

		return ConVar.Server.encryption;
	}

	#region Patches

	[AutoPatch, HarmonyPatch(typeof(EACServer), nameof(EACServer.OnJoinGame))]
	[UsedImplicitly]
	private class NoEAC_OnJoinGame
	{
		[HarmonyPrefix]
		[UsedImplicitly]
		private static bool Prefix(Connection connection)
		{
			try
			{
				if (CanBypass(connection))
				{
					#if DEV
					Interface.Oxide.LogInfo($"Phase 1 {connection}");
					#endif
					EACServer.OnAuthenticatedLocal(connection);
					EACServer.OnAuthenticatedRemote(connection);
					
					return false;
				}
			}
			catch (Exception e)
			{
				Interface.Oxide.LogWarning($"Phase 1 failed for {connection.userid}", e);
			}

			
			return true;
		}
	}

	[AutoPatch, HarmonyPatch(typeof(ServerMgr), nameof(ServerMgr.JoinGame))]
	[UsedImplicitly]
	private static class ServerMgr_JoinGame
	{
		[HarmonyTranspiler]
		[UsedImplicitly]
		private static IEnumerable<CodeInstruction> Transpiler(IEnumerable<CodeInstruction> op)
		{
			List<CodeInstruction> IL = new(op);
			for (int index = 0; index < IL.Count; index++)
			{
				CodeInstruction CIL = IL[index];
				if (CIL.opcode == OpCodes.Ldfld && CIL.operand is FieldInfo
				    {
					    Name: "encryption", DeclaringType.Name: "Server"
				    })
				{
					CIL.opcode = OpCodes.Ldarg_1;
					CIL.operand = null;
					IL.Insert(index + 1,
						new CodeInstruction(OpCodes.Call,
							AccessTools.Method(typeof(NoEAC), nameof(UserEncryptionOverride))));
					index++;
				}
			}

			return IL;
		}
	}

	#endregion
}
