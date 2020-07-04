//
//@TheJokiv 
//@UEFI

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.mem.MemoryBlock;

public class TransferEfiFilesToProject extends HeadlessScript {

	@Override
	protected void run() throws Exception {
		String folderName = null;

		if (this.isRunningHeadless()) {
			MemoryBlock childSmiBlock = this.getMemoryBlock("childSmi");
			MemoryBlock regInterBlock = this.getMemoryBlock("regInterrupt");
			this.setHeadlessImportDirectory(null);
			String[] args = getScriptArgs();
			if (args.length < 1)
				return;
			setHeadlessContinuationOption(HeadlessContinuationOption.CONTINUE);
			
			if (childSmiBlock != null) {
				folderName = "ChildInterrupts";
				print("ChildInterrupt found");
			}
			else {
				print("No ChildInterrupt in module!");
			}
			if (regInterBlock != null) {
				byte[] raw = new byte[(int) regInterBlock.getSize()];
				regInterBlock.getBytes(regInterBlock.getStart(), raw);
				String str = new String(raw);
				str = str.substring(1, str.length() - 1);

				String[] regInter = str.split("[, =]");
				for (int i = 0; i < regInter.length; i++) {
					switch (regInter[i]) {
					case ("gpiHandler"):
					case ("ichnHandler"):
					case ("ioTrapHandler"):
					case ("periodicTimerHandler"):
					case ("pwrButtonHandler"):
					case ("sxHandler"):
					case ("usbHandler"):
					case ("standbyButtonHandler"):
					case ("pchTcoHandler"):
					case ("pchPcieHandler"):
					case ("pchAcpiHandler"):
					case ("pchGpioUnlockHandler"):
					case ("pchHandler"):
					case ("pchEspiHandler"):
					case ("acpiEnHandler"):
					case ("acpiDisHandler"):
						if (folderName == null || folderName.equalsIgnoreCase("UnknownInterrupts")) 
							folderName = "HwInterrupts";
						print("HwInterrupt found");
						break;
					case ("Unknown"):
						if (folderName == null)
							folderName = "UnknownInterrupts";
						print("UnknownInterrupt found");
						break;
					case ("swSmiHandler"):
						folderName = "SwInterrupts";
						print("SwInterrupt found");
						break;
					}
					if (folderName.compareTo("SwInterrupts") == 0)
						break;
				}
			} 
			else {
				print("No Sw/HwItterupts in module!");
			}

			if (folderName != null) {
				this.setHeadlessImportDirectory(args[0] + "/" + folderName);
			}
		}
	}
}
