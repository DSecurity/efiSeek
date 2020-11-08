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

package efiSeek;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import ghidra.program.model.data.*;
import ghidra.util.exception.CancelledException;
import org.json.JSONObject;

import ghidra.framework.Application;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import static ghidra.program.model.data.DataTypeConflictHandler.*;



import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;


public class EfiSeek extends EfiUtils {
	private Memory mem;
	private Address imageBase;
	private DataTypeManager uefiHeadersArchive = null;
	private Path guidBasePath = null;
	private HashMap<String, String> guids = new HashMap<>();
	private Integer nameCount = 0;
	private VarnodeConverter varnodeConverter = null;

	private JSONObject meta = new JSONObject();
	private JSONObject locateProtocol = new JSONObject();
	private JSONObject installProtocol = new JSONObject();
	private JSONObject interrupts = new JSONObject();
	private JSONObject childSmi = new JSONObject();
	private JSONObject swSmi = new JSONObject();
	private JSONObject hwSmi = new JSONObject();
	
	private HashMap<Function, DecompileResults> decompileFunction = new HashMap<>();

	private String[] uefiFuncList = new String[] { "EFI_LOCATE_PROTOCOL", "EFI_SMM_GET_SMST_LOCATION2",
			"EFI_LOCATE_PROTOCOL", "EFI_SMM_REGISTER_PROTOCOL_NOTIFY", "REGISTER", "EFI_INSTALL_PROTOCOL_INTERFACE" };

	public EfiSeek(Program prog, String gdtFileName) {
		this.currentProgram = prog;
		this.imageBase = prog.getImageBase();
		this.monitor = TaskMonitor.DUMMY;
		this.mem = getCurrentProgram().getMemory();
		this.varnodeConverter = new VarnodeConverter(prog);
 
		try {
			FileDataTypeManager externalHeadersArchive = FileDataTypeManager
					.openFileArchive(Application.getModuleDataFile("efiSeek", gdtFileName), false);
			List<DataType> allHeaders = new ArrayList<DataType>();
			externalHeadersArchive.getAllDataTypes(allHeaders);

			this.uefiHeadersArchive = prog.getDataTypeManager();
			this.uefiHeadersArchive.addDataTypes(allHeaders, KEEP_HANDLER, this.monitor);

		} catch (IOException | CancelledException e) {
			Msg.error(this, "error open " + gdtFileName);
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
		this.getMeta();
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
					this.hwSmi.put("gpiHandler", true);
					break;
				case ("EFI_SMM_ICHN_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("ichnHandler", true);
					break;
				case ("EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("ioTrapHandler", true);
					break;
				case ("EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("periodicTimerHandler", true);
					break;
				case ("EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("pwrButtonHandler", true);
					break;
				case ("EFI_SMM_SX_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("sxHandler", true);
					break;
				case ("EFI_SMM_USB_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("usbHandler", true);
					break;
				case ("EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID"):
					this.hwSmi.put("standbyButtonHandler", true);
					break;
				case ("PCH_TCO_SMI_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("pchTcoHandler", true);
					break;
				case ("PCH_PCIE_SMI_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("pchPcieHandler", true);
					break;
				case ("PCH_ACPI_SMI_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("pchAcpiHandler", true);
					break;
				case ("PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("pchGpioUnlockHandler", true);
					break;
				case ("PCH_SMI_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("pchHandler", true);
					break;
				case ("PCH_ESPI_SMI_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("pchEspiHandler", true);
					break;
				case ("EFI_ACPI_EN_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("acpiEnHandler", true);
					break;
				case ("EFI_ACPI_DIS_DISPATCH_PROTOCOL_GUID"):
					this.hwSmi.put("acpiDisHandler", true);
					break;
				case ("EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID"):
					this.swSmi.put("swSmiHandler", true);
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

	private void getSmstLocation2(PcodeOpAST pCode) throws Exception {
		pCode = this.checkFuncParams(pCode, "EFI_SMM_GET_SMST_LOCATION2", 2);
		
		if(pCode == null) {
			return;
		}
		
		this.varnodeConverter.newVarnode(pCode.getInput(2));

		DataType smstType = this.uefiHeadersArchive.getDataType("/behemot.h/EFI_SMM_SYSTEM_TABLE2 *");
		if (varnodeConverter.isGlobal()) {
			this.defineData(varnodeConverter.getGlobalAddress(), smstType, "gSmst" + this.nameCount, null);
		} else if (varnodeConverter.isLocal()) {
			this.defineVar(varnodeConverter.getVariable(), smstType, "Smst" + this.nameCount);
			this.nameCount++;
			
		}
	}
	
	private String guidNameToProtocolName(String name) {
		String protName = name.substring(0, name.length() - 5);
		return protName;
	}
	
	private void locateProtocol(PcodeOpAST pCode) throws Exception {
		pCode = this.checkFuncParams(pCode, "EFI_LOCATE_PROTOCOL", 3);
		if(pCode == null) {
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
			this.defineData(varnodeConverter.getGlobalAddress(), interfaceType, "g" + interfaceName + "_" + this.nameCount,
					null);
			this.nameCount++;
		} else if (varnodeConverter.isLocal()) {
			this.defineVar(varnodeConverter.getVariable(), interfaceType, interfaceName + this.nameCount);
			this.nameCount++;
		}
		Address pCodeAddress = pCode.getSeqnum().getTarget();
		long pCodeOffset = pCodeAddress.subtract(this.imageBase);

		JSONObject protocol = new JSONObject();
		protocol.put("name", interfaceName);
		protocol.put("function name", this.getFunctionBefore(pCodeAddress).getName());
		protocol.put("guid", guid.toString());
		this.locateProtocol.put(String.valueOf(pCodeOffset), protocol);
	}

	private void installProtocol(PcodeOpAST pCode) throws Exception {
		pCode = this.checkFuncParams(pCode, "EFI_INSTALL_PROTOCOL_INTERFACE" , 4);
		
		if(pCode == null) {
			return;
		}

		this.varnodeConverter.newVarnode(pCode.getInput(1));

		if (varnodeConverter.isLocal()) {
			this.defineVar(varnodeConverter.getVariable(), this.uefiHeadersArchive.getDataType("/behemot.h/EFI_HANDLE *"), "Handle" + this.nameCount);
			this.nameCount++;
		} else if (varnodeConverter.isGlobal()) {
			this.defineData(varnodeConverter.getGlobalAddress(),
					this.uefiHeadersArchive.getDataType("/behemot.h/EFI_HANDLE *"), "g" + "Handle" + this.nameCount,
					null);
			this.nameCount++;
		}
		Guid guid = defineGuid(pCode.getInput(2));
		String strGuid = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF";
		String interfaceName = null;
		DataType interfaceType = null;
		
		if (guid != null) {
			if (this.guids.containsKey(guid.toString())) {
				interfaceName = this.guidNameToProtocolName(this.guids.get(guid.toString()));
			}
			strGuid = guid.toString();
			Msg.info(this, strGuid);
		}
		if (interfaceType == null)
			interfaceType = this.uefiHeadersArchive.getDataType("/behemot.h/INT64 *");
		if (interfaceName == null)
			interfaceName = "unknownProtocol_" + strGuid.substring(0, 8);
		
		this.varnodeConverter.newVarnode(pCode.getInput(4));
		
			if (varnodeConverter.isGlobal()) {
				interfaceType = this.uefiHeadersArchive.getDataType(
						"/behemot.h/" + interfaceName);
				if (interfaceType == null) {
					interfaceType = this.uefiHeadersArchive.getDataType("/behemot.h/INT64");
				}
				this.defineData(varnodeConverter.getGlobalAddress(), interfaceType, "g" + interfaceName + "_" + this.nameCount,
						null);
				this.nameCount++;
			} else if (varnodeConverter.isLocal()) {
				this.defineVar(varnodeConverter.getVariable(), interfaceType, interfaceName + this.nameCount);
				this.nameCount++;
			}
		
		Address pCodeAddress = pCode.getSeqnum().getTarget();
		long pCodeOffset = pCodeAddress.subtract(this.imageBase);

		JSONObject protocol = new JSONObject();
		protocol.put("name", interfaceName);
		protocol.put("function name", this.getFunctionBefore(pCodeAddress).getName());
		protocol.put("guid", strGuid);
		this.installProtocol.put(String.valueOf(pCodeOffset), protocol);
	}

	private void Reg2(PcodeOpAST pCode) throws Exception {
				
		FunctionDefinition funcProt = (FunctionDefinition) this.uefiHeadersArchive
				.getDataType("/behemot.h/functions/EFI_SMM_HANDLER_ENTRY_POINT2");
		JSONObject root = this.hwSmi;
		String funcName = null;
		String fdefName = null;	
		Address funcAddress = null;
		
		
		switch (pCode.getInput(0).getHigh().getDataType().getName()) {
		case ("EFI_SMM_POWER_BUTTON_REGISTER2"):
			funcName = "pwrButtonHandler";
			fdefName = "EFI_SMM_POWER_BUTTON_REGISTER2";
			break;
		case ("EFI_SMM_SX_REGISTER2"):
			funcName = "sxHandler";
			fdefName = "EFI_SMM_SX_REGISTER2";
			break;
		case ("EFI_SMM_SW_REGISTER2"):
			funcName = "swSmiHandler";
			root = this.swSmi;
			fdefName = "EFI_SMM_SW_REGISTER2";
			break;
		case ("EFI_SMM_PERIODIC_TIMER_REGISTER2"):
			funcName = "periodicTimerHandler";
			fdefName = "EFI_SMM_PERIODIC_TIMER_REGISTER2";
			break;
		case ("EFI_SMM_USB_REGISTER2"):
			funcName = "usbHandler";
			fdefName = "EFI_SMM_USB_REGISTER2";
			break;
		case ("EFI_SMM_IO_TRAP_DISPATCH2_REGISTER"):
			funcName = "ioTrapHandler";
			fdefName = "EFI_SMM_IO_TRAP_DISPATCH2_REGISTER";
			break;
		case ("EFI_SMM_GPI_REGISTER2"):
			funcName = "gpiHandler";
			fdefName = "EFI_SMM_GPI_REGISTER2";
			break;
		case ("EFI_SMM_STANDBY_BUTTON_REGISTER2"):
			funcName = "standbyButtonHandler";
			fdefName = "EFI_SMM_STANDBY_BUTTON_REGISTER2";
			break;
		default:
			funcName = "otherSMI";
			fdefName = null;
			break;
		}
			
		pCode = this.checkFuncParams(pCode, fdefName, 3);
		
		if(pCode == null) {
			return;
		}		
		
		this.varnodeConverter.newVarnode(pCode.getInput(2));
		
		if (varnodeConverter.isGlobal()) {
			funcAddress = varnodeConverter.getGlobalAddress();
			if (varnodeConverter.isRef()) {
				funcAddress = readAddr(varnodeConverter.getGlobalAddress());
			}
			funcName = funcName + this.nameCount;
			this.createFunctionFormDifinition(funcAddress, funcProt, funcName);
			this.nameCount++;
		}
		
		Address pCodeAddress = pCode.getSeqnum().getTarget();
		long pCodeOffset = pCodeAddress.subtract(this.imageBase);

		JSONObject iter = new JSONObject();
		if(funcAddress !=null) {
			long funcOffset = funcAddress.subtract(this.imageBase);
			iter.put("function offset", String.valueOf(funcOffset));
			iter.put("function name", funcName);
		}
		else {
			iter.put("function offset", "");
			iter.put("function name", "");
		}
		root.put(String.valueOf(pCodeOffset), iter);
	}
	
	private void childIterReg(PcodeOpAST pCode) throws Exception {
		pCode = this.checkFuncParams(pCode, "EFI_SMM_INTERRUPT_REGISTER", 3);
		
		if(pCode == null) {
			return;
		}
		
		this.varnodeConverter.newVarnode(pCode.getInput(1));

		FunctionDefinition funcProt = (FunctionDefinition) this.uefiHeadersArchive
				.getDataType("/behemot.h/functions/EFI_SMM_HANDLER_ENTRY_POINT2");
		Address funcAddress = null;
		String funcName = "";
		
		if (varnodeConverter.isGlobal()) {
			funcName = "ChildSmiHandler" + this.nameCount;
			funcAddress = varnodeConverter.getGlobalAddress();
			this.createFunctionFormDifinition(funcAddress, funcProt,
					funcName);
			this.nameCount++;
		}
		String strGuid = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF";
		Guid guid = this.defineGuid(pCode.getInput(2));
		String name = "";
		
		if (guid != null) {
			if (this.guids.containsKey(guid.toString())) {
				name = this.guidNameToProtocolName(this.guids.get(guid.toString()));
			}
			strGuid = guid.toString();
		}

		JSONObject iter = new JSONObject();
		iter.put("guid", strGuid);
		iter.put("name", name);
		if(funcAddress !=null) {
			long funcOffset = funcAddress.subtract(this.imageBase);
			iter.put("function offset", String.valueOf(funcOffset));
			iter.put("function name", funcName);
		}
		else {
			iter.put("function offset", "");
			iter.put("function name", "");
		}
		long pCodeOffset = pCode.getParent().getStart().subtract(this.imageBase);
		this.childSmi.put(String.valueOf(pCodeOffset), iter);
	}

	private void regProtocolNotify(PcodeOpAST pCode) throws Exception {
		pCode = this.checkFuncParams(pCode, "EFI_REGISTER_PROTOCOL_NOTIFY", 3);
		
		if(pCode == null) {
			return;
		}
		
		String strGuid = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF";
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
	
	private PcodeOpAST checkFuncParams(PcodeOpAST pCode, String fdefName, Integer correctNumberOfParams) throws ParseException {
		Program program = this.currentProgram;
		Function func = this.getFunctionBefore(pCode.getParent().getStop());
		Address addr = pCode.getSeqnum().getTarget();
		FunctionSignature fdef = null;
		
		if (fdefName == null) {
			DataTypeManager dtm = this.currentProgram.getDataTypeManager();
			CParser parser = new CParser(dtm);
			fdefName = "";
			for (Integer i = 0; i < correctNumberOfParams; i++) {
				fdefName = fdefName + "void * param" + i + ", ";
			}
			fdefName = "EFI_STATUS func(" + fdefName.substring(0, fdefName.length() - 2) + ");";
				fdef = (FunctionSignature)parser.parse(fdefName);
		}
		else {
			fdef = (FunctionSignature)this.uefiHeadersArchive.getDataType("/behemot.h/functions/" + fdefName);
		}
		
		correctNumberOfParams = fdef.getArguments().length;
		if(correctNumberOfParams != pCode.getNumInputs() - 1) {
			Msg.warn(this, "Wrong number of the parameters for" + fdefName + " func at the address: " + pCode.getSeqnum().getTarget().toString());
			Msg.warn(this, "Trying to recover");
			int transaction = program.startTransaction("Override Signature");
			boolean commit = false;
			try {
				HighFunctionDBUtil.writeOverride(func, addr, fdef);
				commit = true;
			}
			catch (Exception e) {
				Msg.error(this, "Error overriding signature: " + e);
			}
			finally {
				program.endTransaction(transaction, commit);
			}
			pCode = updateCallIndPcode(pCode);
			if(correctNumberOfParams != pCode.getNumInputs() - 1) {
				Msg.error(this, "Recovery failed");
				return null;
			}
		}
		return pCode;
	}
	
	private PcodeOpAST updateCallIndPcode(PcodeOpAST pCode) {
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(this.getCurrentProgram());
		
		DecompileResults res = decomp.decompileFunction(this.getFunctionBefore(pCode.getParent().getStop()), 60, this.monitor);
		HighFunction highFunc = res.getHighFunction();
		
		Iterator<PcodeOpAST> pCodeAtAddr = highFunc.getPcodeOps(pCode.getSeqnum().getTarget());
		while(pCodeAtAddr.hasNext()) {
			PcodeOpAST currentPcode = pCodeAtAddr.next();
			if (currentPcode.getOpcode() ==  PcodeOp.CALLIND) {
				return currentPcode;
			}
		}
		return pCode;
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
			this.defineVar(varnodeConverter.getVariable(), this.uefiHeadersArchive.getDataType("/behemot.h/EFI_GUID"), "Guid" + this.nameCount);
			this.nameCount++;
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
				else {
					if(this.decompileFunction.containsKey(funcWithCallInd.get(j))){
						this.decompileFunction.remove(funcWithCallInd.get(j));
						this.decompileFunction.put(funcWithCallInd.get(j), res);
					}
					else {
						this.decompileFunction.put(funcWithCallInd.get(j), res);
					}					
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
		this.createMeta();
		if (this.currentProgram.isLocked() == false)
			saveMeta();
	}

	private void createMeta() {
		 this.meta.put("locate protocol", this.locateProtocol);
		 this.meta.put("locate protocol", this.locateProtocol);
		 this.meta.put("install protocol", this.installProtocol);
		 
		 this.interrupts.put("child", this.childSmi);
		 this.interrupts.put("swSmi", this.swSmi);
		 this.interrupts.put("hwSmi", this.hwSmi);
		 
		 this.meta.put("interrupts", this.interrupts);
	}
	
	private void getMeta() {
		MemoryBlock metaBlock = this.getMemoryBlock("metaBlock");
		if(metaBlock != null) {
			byte[] raw = new byte[(int) metaBlock.getSize()];
			try {
				metaBlock.getBytes(metaBlock.getStart(), raw);
			} catch (MemoryAccessException e) {
				Msg.info(this, "Can't read metaBlock");
				e.printStackTrace();
				return;
			}
			String metaStr = new String(raw);
			this.meta = new JSONObject(metaStr);
			this.locateProtocol = meta.getJSONObject("locate protocol");
			this.installProtocol = meta.getJSONObject("install protocol");
			this.interrupts = meta.getJSONObject("interrupts");
			this.childSmi = interrupts.getJSONObject("child");
			this.swSmi = interrupts.getJSONObject("swSmi");
			this.hwSmi = interrupts.getJSONObject("hwSmi");
		}
	}
	
	private void saveMeta() {
		MemoryBlock metaBlock = this.getMemoryBlock("metaBlock");
		try {
			if (metaBlock != null) {
				this.removeMemoryBlock(metaBlock);
			}
			this.createMemoryBlock("metaBlock", this.toAddr(0), this.meta.toString().getBytes(), true);
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
	
	public void updateMemBlockPermission() {
		if(mem.getBlock("metaBlock") != null) {
			return;
		}
		MemoryBlock[] memBlocks = this.mem.getBlocks();
		
		for(int i = 0; i < memBlocks.length; i++) {
			memBlocks[i].setPermissions(true, true, true);
		}
		
	}
}
