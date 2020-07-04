//	 Copyright (c) 2020 Digital Security. All rights reserved.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package efiseek;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

import ghidra.framework.Application;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class EfiSeek extends EfiUtils {
	private Memory mem;
	private FileDataTypeManager uefiHeadersArchive = null;
	private Path guidBasePath = null;
	private HashMap<String, String> guids = new HashMap<>();
	private Integer nameCount = 0;
	private VarnodeConverter varnodeConverter = null;

//	Guid Address 
	private HashMap<String, Address> locateProtocol = new HashMap<>();
//	Guid Address
	private HashMap<String, Address> installProtocol = new HashMap<>();
//	Guid Address
	private HashMap<String, Address> childSmi = new HashMap<>();
//	Type Address  
	private HashMap<String, Address> regInterrupt = new HashMap<>();

	private String[] uefiFuncList = new String[] { "EFI_LOCATE_PROTOCOL", "EFI_SMM_GET_SMST_LOCATION2",
			"EFI_LOCATE_PROTOCOL", "EFI_SMM_REGISTER_PROTOCOL_NOTIFY", "REGISTER", "EFI_INSTALL_PROTOCOL_INTERFACE" };

	public EfiSeek(Program prog, String gdtFileName) {
		this.currentProgram = prog;
		this.monitor = TaskMonitor.DUMMY;
		this.mem = getCurrentProgram().getMemory();
		this.varnodeConverter = new VarnodeConverter(prog);

		try {
			this.uefiHeadersArchive = FileDataTypeManager
					.openFileArchive(Application.getModuleDataFile("efiSeek", gdtFileName), false);
		} catch (IOException e) {
			Msg.error(this, "error open Behemoth.gdt");
			e.printStackTrace();
			return;
		}
		try {
			this.guidBasePath = Paths
					.get(Application.getModuleDataFile("efiSeek", "guids-db.ini").getAbsolutePath());
		} catch (FileNotFoundException e) {
			Msg.error(this, "error open guids-db.ini");
			e.printStackTrace();
		}
		this.parseGuidsBase();
	}

	private void parseGuidsBase() {
		String guidSrt = null;
		try {
			guidSrt = Files.readString(this.guidBasePath);
		} catch (IOException e) {
			Msg.error(this, "Problem with path to guid-db file");
			e.printStackTrace();
		}
		String delims = "[ {}=\n\r\t]+";

		String[] tempGuids = guidSrt.split(delims);
		for (int j = 0; j < tempGuids.length; j += 2) {
			if (tempGuids[j].compareToIgnoreCase("[EDK]") == 0 || tempGuids[j].compareToIgnoreCase("[AMI]") == 0
					|| tempGuids[j].compareToIgnoreCase("[Apple]") == 0
					|| tempGuids[j].compareToIgnoreCase("[INTEL]") == 0
					|| tempGuids[j].compareToIgnoreCase("[NEW]") == 0 || tempGuids[j].compareToIgnoreCase("[NEW]") == 0
					|| tempGuids[j].compareToIgnoreCase("[INSYDE]") == 0
					|| tempGuids[j].compareToIgnoreCase("[ACER]") == 0
					|| tempGuids[j].compareToIgnoreCase("[AMI+]") == 0
					|| tempGuids[j].compareToIgnoreCase("[PHOENIX]") == 0) {
				j++;
			}
			this.guids.put(tempGuids[j + 1], tempGuids[j]);
		}
	}

	public void findGuids() {
		Address start = this.mem.getMinAddress();
		Address end = this.mem.getMaxAddress();

		for (Address Addr = start; Addr.getOffset() + 4 < end.getOffset(); Addr = Addr.add(4)) {
			byte[] rawGuid = new byte[16];
			try {
				this.mem.getBytes(Addr, rawGuid);
			} catch (MemoryAccessException e) {
				continue;
			}
			String strGuid = new Guid(rawGuid).toString();
			if (strGuid.compareToIgnoreCase("00000000-0000-0000-0000-000000000000") == 0) {
				continue;
			}
			if (this.guids.containsKey(strGuid)) {
				Msg.info(this, this.guids.get(strGuid));
				switch (this.guids.get(strGuid)) {
				case ("EFI_SMM_GPI_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("gpiHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_ICHN_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("ichnHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("ioTrapHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("periodicTimerHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("pwrButtonHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_SX_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("sxHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_USB_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("usbHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("standbyButtonHandler", this.toAddr(0x0));
					break;
				case ("PCH_TCO_SMI_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("pchTcoHandler", this.toAddr(0x0));
					break;
				case ("PCH_PCIE_SMI_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("pchPcieHandler", this.toAddr(0x0));
					break;
				case ("PCH_ACPI_SMI_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("pchAcpiHandler", this.toAddr(0x0));
					break;
				case ("PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("pchGpioUnlockHandler", this.toAddr(0x0));
					break;
				case ("PCH_SMI_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("pchHandler", this.toAddr(0x0));
					break;
				case ("PCH_ESPI_SMI_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("pchEspiHandler", this.toAddr(0x0));
					break;
				case ("EFI_ACPI_EN_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("acpiEnHandler", this.toAddr(0x0));
					break;
				case ("EFI_ACPI_DIS_DISPATCH_PROTOCOL_GUID"):
					this.regInterrupt.put("acpiDisHandler", this.toAddr(0x0));
					break;
				case ("EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID"):
					this.regInterrupt.put("swSmiHandler", this.toAddr(0x0));
					break;
				default:
					break;
				}
				try {
					this.defineData(Addr, this.uefiHeadersArchive.getDataType("/behemot.h/EFI_GUID"),
							this.guids.get(strGuid), null);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	private void setMain() throws Exception {
		Address addrEntryPoint = this.getEntryPoint();
		FunctionDefinition funcProt = (FunctionDefinition) this.uefiHeadersArchive
				.getDataType("/behemot.h/functions/_ModuleEntryPoint");
		this.createFunctionFormDifinition(addrEntryPoint, funcProt, "ModuleEntryPoint");
	}

	private String guidNameToProtocolName(String name) {
		String protName = name.substring(0, name.length() - 5);
		return protName;
	}

	private void locateProtocol(PcodeOpAST pCode) throws Exception {
		if (pCode.getInputs().length != 4) {
			Msg.error(this, "Wrong number of parameters for locateProtocol func "
					+ pCode.getInput(0).getHigh().getHighFunction().getFunction().getName());
			return;
		}
		Guid guid = null;
		guid = this.defineGuid(pCode.getInput(1));
		String interfaceName = null;
		DataType interfaceType = null;

		if (guid != null) {
			Msg.info(this, guid.toString());
			if (this.guids.containsKey(guid.toString())) {
				interfaceType = this.uefiHeadersArchive.getDataType(
						"/behemot.h/" + this.guidNameToProtocolName(this.guids.get(guid.toString())) + " *");
				interfaceName = this.guidNameToProtocolName(this.guids.get(guid.toString()));
			}
		} else
			guid = new Guid("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF");

		if (interfaceType == null)
			interfaceType = this.uefiHeadersArchive.getDataType("/behemot.h/INT64 *");
		if (interfaceName == null)
			interfaceName = "unknownProtocol_" + guid.toString().substring(0, 8);

		this.varnodeConverter.newVarnode(pCode.getInput(3));

		if (varnodeConverter.isGlobal()) {
			String name = this.getSymbolAt(varnodeConverter.getGlobalAddress()).getName();
			if (name.substring(0, 2) == "EFI") {
				return;
			}
			this.defineData(varnodeConverter.getGlobalAddress(), interfaceType, "g" + interfaceName + this.nameCount,
					null);
			this.nameCount++;
		} else if (varnodeConverter.isLocal()) {
			String name = varnodeConverter.getVariable().getName();
			if (name.substring(0, 2) == "EFI") {
				return;
			}
			varnodeConverter.getVariable().setName(interfaceName + this.nameCount, SourceType.USER_DEFINED);
			varnodeConverter.getVariable().setDataType(interfaceType, SourceType.USER_DEFINED);
			this.nameCount++;
		}
		this.locateProtocol.put(guid.toString(), pCode.getParent().getStart());
	}

	private void installProtocol(PcodeOpAST pCode) throws Exception {
		if (pCode.getInputs().length != 5) {
			Msg.error(this, "Wrong number of parameters for installProtocol func"
					+ pCode.getInput(0).getHigh().getHighFunction().getFunction().getName());
			return;
		}

		this.varnodeConverter.newVarnode(pCode.getInput(1));

		if (varnodeConverter.isLocal()) {
			varnodeConverter.getVariable().setName("Handle" + this.nameCount, SourceType.USER_DEFINED);
			varnodeConverter.getVariable().setDataType(this.uefiHeadersArchive.getDataType("/behemot.h/EFI_HANDLE *"),
					SourceType.USER_DEFINED);
			this.nameCount++;
		} else if (varnodeConverter.isGlobal()) {
			this.defineData(varnodeConverter.getGlobalAddress(),
					this.uefiHeadersArchive.getDataType("/behemot.h/EFI_HANDLE *"), "g" + "Handle" + this.nameCount,
					null);
			this.nameCount++;
		}
		Guid guid = defineGuid(pCode.getInput(2));
		String strGuid = "None";
		if (guid != null) {
			strGuid = guid.toString();
			Msg.info(this, strGuid);
		}
		this.installProtocol.put(strGuid, pCode.getParent().getStart());
	}

	private void getSmstLocation2(PcodeOpAST pCode) throws Exception {
		if (pCode.getInputs().length != 3) {
			Msg.error(this, "Wrong number of parameters for getSmstLocation2 func "
					+ pCode.getInput(0).getHigh().getHighFunction().getFunction().getName());
			return;
		}
		this.varnodeConverter.newVarnode(pCode.getInput(2));

		DataType smstType = this.uefiHeadersArchive.getDataType("/behemot.h/EFI_SMM_SYSTEM_TABLE2 *");
		if (varnodeConverter.isGlobal()) {
			this.defineData(varnodeConverter.getGlobalAddress(), smstType, "gSmst" + this.nameCount, null);
		} else if (varnodeConverter.isLocal()) {
			varnodeConverter.getVariable().setName("Smst" + this.nameCount, SourceType.USER_DEFINED);
			this.nameCount++;
			varnodeConverter.getVariable().setDataType(smstType, SourceType.USER_DEFINED);
		}
	}

	private void Reg2(PcodeOpAST pCode) throws Exception {
		if (pCode.getInputs().length != 5) {
			Msg.error(this, "Wrong number of parameters for swReg func "
					+ pCode.getInput(0).getHigh().getHighFunction().getFunction().getName());
			this.regInterrupt.put("Unknown", this.toAddr(0));
			return;
		}
		this.varnodeConverter.newVarnode(pCode.getInput(2));

		FunctionDefinition funcProt = (FunctionDefinition) this.uefiHeadersArchive
				.getDataType("/behemot.h/functions/EFI_SMM_HANDLER_ENTRY_POINT2");
		String name = null;
		if (varnodeConverter.isGlobal()) {
			switch (pCode.getInput(0).getHigh().getDataType().getName()) {
			case ("EFI_SMM_POWER_BUTTON_REGISTER2"):
				name = "pwrButtonHandler";
				break;
			case ("EFI_SMM_SX_REGISTER2"):
				name = "sxHandler";
				break;
			case ("EFI_SMM_SW_REGISTER2"):
				name = "swSmiHandler";
				break;
			case ("EFI_SMM_PERIODIC_TIMER_REGISTER2"):
				name = "periodicTimerHandler";
				break;
			case ("EFI_SMM_USB_REGISTER2"):
				name = "usbHandler";
				break;
			case ("EFI_SMM_IO_TRAP_DISPATCH2_REGISTER"):
				name = "ioTrapHandler";
				break;
			case ("EFI_SMM_GPI_REGISTER2"):
				name = "gpiHandler";
				break;
			case ("EFI_SMM_STANDBY_BUTTON_REGISTER2"):
				name = "standbyButtonHandler";
				break;
			}
			Address addrFunc = varnodeConverter.getGlobalAddress();
			if (varnodeConverter.isRef()) {
				addrFunc = readAddr(varnodeConverter.getGlobalAddress());
			}
			this.createFunctionFormDifinition(addrFunc, funcProt, name + this.nameCount);
			this.nameCount++;
		}
		this.regInterrupt.put(name, pCode.getParent().getStart());
	}

	private void childIterReg(PcodeOpAST pCode) throws Exception {
		if (pCode.getInputs().length != 4) {
			Msg.error(this, "Wrong number of parameters for childIterReg func "
					+ pCode.getInput(0).getHigh().getHighFunction().getFunction().getName());
			this.regInterrupt.put("", this.toAddr(0));
			return;
		}
		this.varnodeConverter.newVarnode(pCode.getInput(1));

		FunctionDefinition funcProt = (FunctionDefinition) this.uefiHeadersArchive
				.getDataType("/behemot.h/functions/EFI_SMM_HANDLER_ENTRY_POINT2");
		if (varnodeConverter.isGlobal()) {
			this.createFunctionFormDifinition(varnodeConverter.getGlobalAddress(), funcProt,
					"ChildSmiHandler" + this.nameCount);
			this.nameCount++;
		}
		String strGuid = "None";
		Guid guid = this.defineGuid(pCode.getInput(2));
		if (guid != null)
			strGuid = guid.toString();

		this.childSmi.put(strGuid, pCode.getParent().getStart());
	}

	private void regProtocolNotify(PcodeOpAST pCode) throws Exception {
		if (pCode.getInputs().length != 4) {
			Msg.error(this, "Wrong number of parameters for regProtocolNotify func "
					+ pCode.getInput(0).getHigh().getHighFunction().getFunction().getName());
			return;
		}
		String strGuid = "None";
		Guid guid = this.defineGuid(pCode.getInput(1));
		if (guid != null) {
			strGuid = guid.toString();
			Msg.info(this, strGuid);
		}
		this.varnodeConverter.newVarnode(pCode.getInput(2));

		if (varnodeConverter.isGlobal()) {
			this.createFunctionFormDifinition(varnodeConverter.getGlobalAddress(),
					(FunctionDefinition) this.uefiHeadersArchive.getDataType("/behemot.h/functions/EFI_SMM_NOTIFY_FN"),
					"notify_" + strGuid.substring(0, 8));
		}

	}

	private Guid defineGuid(Varnode guidVar) throws Exception {
		String name = null;
		Guid guid = null;
		this.varnodeConverter.newVarnode(guidVar);

		if (varnodeConverter.isGlobal()) {
			Address guidAddr = varnodeConverter.getGlobalAddress();
			byte[] rawGuid = new byte[16];
			this.mem.getBytes(guidAddr, rawGuid);
			guid = new Guid(rawGuid);
			name = this.getLabel(guidAddr);
			if (name == null) {
				name = "unknownProtocol_" + guid.toString().substring(0, 8);
			}
			this.defineData(guidAddr, this.uefiHeadersArchive.getDataType("/behemot.h/EFI_GUID"), name, null);
		} else if (varnodeConverter.isLocal()) {
			name = "Guid" + this.nameCount;
			varnodeConverter.getVariable().setName(name, SourceType.USER_DEFINED);
			varnodeConverter.getVariable().setDataType(this.uefiHeadersArchive.getDataType("/behemot.h/EFI_GUID"),
					false, true, SourceType.USER_DEFINED);
		}
		return guid;
	}

	public void defineUefiFunctions() throws Exception {

		DecompInterface decomp = new DecompInterface();

		decomp.openProgram(this.getCurrentProgram());
		ArrayList<Function> funcWithCallInd = new ArrayList<Function>();
		for (Function func = this.getFirstFunction(); func != null; func = this.getFunctionAfter(func)) {
			funcWithCallInd.add(func);
		}
		for (int i = 0; i < this.uefiFuncList.length; i++) {
			HashSet<PcodeOpAST> callInd = new HashSet<PcodeOpAST>();
			int size = funcWithCallInd.size();
			for (int j = 0; j < size; j++) {
				DecompileResults res = decomp.decompileFunction(funcWithCallInd.get(j), 120, this.getMonitor());
				HighFunction hifunc = res.getHighFunction();
				if (hifunc == null)
					continue;
				Iterator<PcodeOpAST> pCodeIter = hifunc.getPcodeOps();
				int callIndCount = 0;
				while (pCodeIter.hasNext()) {
					PcodeOpAST pCode = pCodeIter.next();
					if (pCode.getOpcode() == PcodeOp.CALLIND) {
						callIndCount++;
						String callIndType = pCode.getInput(0).getHigh().getDataType().getName();
						if (this.uefiFuncList[i].compareTo("REGISTER") == 0) {
							if (callIndType.length() < 11)
								continue;
							callIndType = callIndType.substring(callIndType.length() - 9, callIndType.length());
							char first = callIndType.charAt(0);
							if (first == '_') {
								callIndType = callIndType.substring(1, callIndType.length());
							} else {
								callIndType = callIndType.substring(0, callIndType.length() - 1);
							}
						}
						if (callIndType.compareToIgnoreCase(this.uefiFuncList[i]) == 0) {
							callInd.add(pCode);
						}
					}
				}
				if (callIndCount == 0) {
					funcWithCallInd.remove(j);
					j--;
					size = funcWithCallInd.size();
				}
			}
			Iterator<PcodeOpAST> callIndIter = callInd.iterator();
			while (callIndIter.hasNext()) {
				PcodeOpAST pCode = callIndIter.next();
				String funcName = pCode.getInput(0).getHigh().getHighFunction().getFunction().getName();
				switch (pCode.getInput(0).getHigh().getDataType().getName()) {
				case ("EFI_LOCATE_PROTOCOL"):
					Msg.info(this, "Locate Protocol in " + funcName);
					this.locateProtocol(pCode);
					break;
				case ("EFI_SMM_GET_SMST_LOCATION2"):
					Msg.info(this, "EFI_SMM_GET_SMST_LOCATION2 in " + funcName);
					this.getSmstLocation2(pCode);
					break;
				case ("EFI_SMM_POWER_BUTTON_REGISTER2"):
				case ("EFI_SMM_SX_REGISTER2"):
				case ("EFI_SMM_SW_REGISTER2"):
				case ("EFI_SMM_PERIODIC_TIMER_REGISTER2"):
				case ("EFI_SMM_USB_REGISTER2"):
				case ("EFI_SMM_IO_TRAP_DISPATCH2_REGISTER"):
				case ("EFI_SMM_GPI_REGISTER2"):
					Msg.info(this, "Some Handle Reg in " + funcName);
					this.Reg2(pCode);
					break;
				case ("EFI_SMM_INTERRUPT_REGISTER"):
					Msg.info(this, "Chilld Smi in " + funcName);
					this.childIterReg(pCode);
					break;
				case ("EFI_INSTALL_PROTOCOL_INTERFACE"):
					Msg.info(this, "Install Protocol in " + funcName);
					this.installProtocol(pCode);
					break;
				case ("EFI_SMM_REGISTER_PROTOCOL_NOTIFY"):
					Msg.info(this, "Registe protocol notify in " + funcName);
					this.regProtocolNotify(pCode);
					break;
				default:
					break;
				}
			}
		}
		decomp.closeProgram();
		if (this.currentProgram.isLocked() == false)
			saveMeta();
	}

	private void saveMeta() {

		MemoryBlock childSmiBlock = this.getMemoryBlock("childSmi");
		MemoryBlock locateProtocolBlock = this.getMemoryBlock("locateProtocol");
		MemoryBlock regInterruptBlock = this.getMemoryBlock("regInterrupt");
		MemoryBlock installProtocolBlock = this.getMemoryBlock("installProtocol");
		try {
			if (!this.childSmi.isEmpty() && childSmiBlock == null)
				this.createMemoryBlock("childSmi", this.toAddr(0), this.childSmi.toString().getBytes(), true);
			if (!this.locateProtocol.isEmpty() && locateProtocolBlock == null)
				this.createMemoryBlock("locateProtocol", this.toAddr(0), this.locateProtocol.toString().getBytes(),
						true);
			if (!this.regInterrupt.isEmpty() && regInterruptBlock == null)
				this.createMemoryBlock("regInterrupt", this.toAddr(0), this.regInterrupt.toString().getBytes(), true);
			if (!this.installProtocol.isEmpty() && installProtocolBlock == null)
				this.createMemoryBlock("installProtocol", this.toAddr(0), this.installProtocol.toString().getBytes(),
						true);
		} catch (Exception e) {
			Msg.error(this, "Can't create memory block with meta. Operation requires exclusive access to object.");
		}
	}

	public void forwardSystemTable() throws Exception {
		this.setMain();
		Function entrtyPoint = this.getFunctionAt(this.getEntryPoint());

		FuncParamForwarding funcParamForwarding = new FuncParamForwarding(this.currentProgram);

		funcParamForwarding.forward(entrtyPoint, 0);
		funcParamForwarding.forward(entrtyPoint, 1);
	}
}