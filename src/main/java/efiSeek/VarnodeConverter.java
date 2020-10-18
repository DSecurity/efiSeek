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

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.HashMap;

public class VarnodeConverter {
	private Address addr = null;
	private Variable finalVar = null;
	private Long constVar = null;
	private ArrayList<Long> offset = new ArrayList<Long>();
	private Boolean deref = false;
	private HashMap<Variable, Long> mulOffset = new HashMap<Variable, Long>();
	
	private FlatProgramAPI flatProgramAPI = null;

	public VarnodeConverter(Program prog) {
		this.flatProgramAPI = new FlatProgramAPI(prog);
	}
	
	public void newVarnode(Varnode inVar) {
		this.addr = null;
		this.finalVar = null;
		this.constVar = null;
		this.offset = new ArrayList<Long>();
		this.deref = false;
		this.mulOffset = new HashMap<Variable, Long>();
		
		this.parsingVarnode(inVar);
	}
	
	private void parsingVarnode(Varnode inVar) {

		switch (inVar.getSpace() & AddressSpace.ID_TYPE_MASK) {
		case AddressSpace.TYPE_REGISTER:
			this.finalVar = this.findVar(inVar);
			return;
		case AddressSpace.TYPE_STACK:
			this.finalVar = this.findVar(inVar);
			return;
		case AddressSpace.TYPE_CONSTANT:
			this.constVar = inVar.getOffset();
			return;
		case AddressSpace.TYPE_RAM:
			this.addr = this.flatProgramAPI.toAddr(inVar.getOffset());
			return;
		default:
			break;
		}

		PcodeOp pCodeDef = inVar.getDef();
		switch (pCodeDef.getMnemonic()) {
		case "CAST":
			this.cast(pCodeDef);
			break;
		case "LOAD":
			this.load(pCodeDef);
			break;
		case "PTRSUB":
			this.ptrSub(pCodeDef);
			break;
		case "INT_ADD":
			this.intAdd(pCodeDef);
			break;
		case "INT_MULT":
			this.intMult(pCodeDef);
			break;
		case "PTRADD":
			this.ptrAdd(pCodeDef);
			break;
		default:
			Msg.error(this, "\nUnknow mnemonic: " + pCodeDef.toString() + "\n");
		}
	}

	private Variable findStackVar(Varnode varnode, int stack_offset) {
		Function func = varnode.getHigh().getHighFunction().getFunction();
		Variable[] vars = func.getLocalVariables();
		int i;
		for (i = 0; i < vars.length; i++) {
			if (vars[i].isStackVariable() && vars[i].getStackOffset() == stack_offset) {
				return vars[i];
			}
		}
		return null;
	}

	private Variable findVar(Varnode inVar) {
		Function func = inVar.getHigh().getHighFunction().getFunction();
		Variable[] vars = func.getAllVariables();
		int i;
		if (inVar.isRegister()) {
			for (i = 0; i < vars.length; i++) {
				if (vars[i].isRegisterVariable() && vars[i].getRegister().getOffset() == inVar.getOffset()) {
					return vars[i];
				}
			}
		} else if ((inVar.getSpace() & AddressSpace.ID_TYPE_MASK) == AddressSpace.TYPE_STACK) {
			for (i = 0; i < vars.length; i++) {
				if (vars[i].isStackVariable() && vars[i].getStackOffset() == inVar.getOffset()) {
					return vars[i];
				}
			}
		}
		return null;
	}

	private boolean checkUnique(PcodeOp pCodeDef) {
		Varnode[] inputs = pCodeDef.getInputs();
		boolean ret = false;
		for (int i = 0; i < inputs.length; i++) {
			if (inputs[i].isUnique()) {
				this.parsingVarnode(inputs[i]);
				ret = true;
			}
		}
		return ret;
	}

	private void cast(PcodeOp pCode) {
		if (this.checkUnique(pCode)) {
			return;
		}
		this.parsingVarnode(pCode.getInput(0));
	}

	private void load(PcodeOp pCode) {
		if (this.checkUnique(pCode)) {
			this.deref = true;
			return;
		}
		Varnode var = pCode.getInput(pCode.getNumInputs() - 1);
		if ((var.getSpace() & AddressSpace.ID_TYPE_MASK) == AddressSpace.TYPE_RAM) {
			this.deref = true;
			this.addr = this.flatProgramAPI.toAddr(var.getOffset());
		} else {
			this.finalVar = this.findVar(var);
		}
	}

	private void ptrSub(PcodeOp pCode) {

		Varnode var1 = pCode.getInput(0);
		Varnode var2 = pCode.getInput(1);

		if (this.checkUnique(pCode)) {
			this.offset.add(var2.getOffset());
			return;
		}
		// check reg and find local var match this reg
		if (var1.isRegister()) {
			// stack pointer; need find var with this stack offset
			if (var1.getOffset() == 0x20) {
				this.finalVar = this.findStackVar(var1, (int) var2.getOffset());
				return;
			}
			this.finalVar = this.findVar(var1);
			this.offset.add(var2.getOffset());

		} else if (var1.isConstant()) {
			this.addr = this.flatProgramAPI.toAddr(var1.getOffset() + var2.getOffset());
			return;
		} else {
			this.addr = this.flatProgramAPI.toAddr(var1.getOffset());
			this.offset.add(var2.getOffset());
		}
	}

	private void intAdd(PcodeOp pCode) {
		Varnode var1 = pCode.getInput(0);
		Varnode var2 = pCode.getInput(1);

		if (this.checkUnique(pCode)) {
			this.offset.add(var2.getOffset());
			return;
		}
		if (var1.isRegister()) {
			if (var1.getOffset() == 0x20) {
				this.finalVar = this.findStackVar(var1, (int) var2.getOffset());
				return;
			}
			this.finalVar = this.findVar(var1);
			this.offset.add(var2.getOffset());
			return;
		} else if (var1.isConstant()) {
			this.addr = this.flatProgramAPI.toAddr(var1.getOffset() + var2.getOffset());
			return;
		} else {
			this.addr = this.flatProgramAPI.toAddr(var1.getOffset());
			this.offset.add(var2.getOffset());
		}
	}

	private void intMult(PcodeOp pCode) {
		Varnode var1 = pCode.getInput(0);
		Varnode var2 = pCode.getInput(1);
		if (this.checkUnique(pCode)) {
			return;
		}
		if (var1.isConstant() && var2.isConstant()) {
			this.offset.add(var1.getOffset() * var2.getOffset());
		} else {
			mulOffset.put(this.findVar(var1), var2.getOffset());
		}
	}

	private void ptrAdd(PcodeOp pCode) {
		Varnode var1 = pCode.getInput(0);
		Varnode var2 = pCode.getInput(1);
		Varnode var3 = pCode.getInput(2);
		
		if (this.checkUnique(pCode)) {
			this.offset.add(var2.getOffset() * var3.getOffset());
			return;
		}
		
		switch (var1.getSpace() & AddressSpace.ID_TYPE_MASK) {
		case AddressSpace.TYPE_REGISTER:
			this.finalVar = this.findVar(var1);
			return;
		case AddressSpace.TYPE_STACK:
			this.finalVar = this.findVar(var1);
			return;
		case AddressSpace.TYPE_CONSTANT:
			this.addr = this.flatProgramAPI.toAddr(var1.getOffset() + (var2.getOffset() * var3.getOffset()));
			return;
		case AddressSpace.TYPE_RAM:
			this.addr = this.flatProgramAPI.toAddr(var1.getOffset());
			this.offset.add(var2.getOffset() * var3.getOffset());
			return;
		default:
			break;
		}
	}

	public boolean isGlobal() {
		if (this.addr != null && this.finalVar == null)
			return true;
		return false;
	}

	public boolean isLocal() {
		if (this.finalVar != null && this.addr == null)
			return true;
		return false;
	}

	public boolean isRef() {
		if (this.deref) {
			return true;
		}
		return false;
	}

	public ArrayList<Long> gettOffset() {
		return this.offset;
	}

	public Variable getVariable() {
		return this.finalVar;
	}

	public Address getGlobalAddress() {
		return this.addr;
	}
}