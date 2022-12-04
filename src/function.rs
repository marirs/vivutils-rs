use vivisect::emulator::OpCode;
use vivisect::workspace::VivWorkspace;

#[derive(Clone, Debug)]
pub struct Function {
    pub workspace: VivWorkspace,
    pub virtual_address: i32,
}

impl Function {
    pub fn new(workspace: VivWorkspace, va: i32) -> Self {
        Function {
            workspace,
            virtual_address: va,
        }
    }

    pub fn basic_blocks(&mut self) -> Vec<BasicBlock> {
        let mut bb = self
            .workspace
            .get_function_blocks(self.virtual_address)
            .iter()
            .map(|(va, size, fva, _)| BasicBlock::new(self.workspace.clone(), *va, *size, *fva))
            .collect::<Vec<_>>();
        bb.sort_by(|x, y| x.virtual_address.partial_cmp(&y.virtual_address).unwrap());
        bb.clone()
    }
}

#[derive(Clone, Debug)]
pub struct BasicBlock {
    pub workspace: VivWorkspace,
    pub virtual_address: i32,
    pub size: i32,
    pub fva: i32,
}

impl BasicBlock {
    pub fn new(workspace: VivWorkspace, va: i32, size: i32, fva: i32) -> Self {
        BasicBlock {
            workspace,
            virtual_address: va,
            size,
            fva,
        }
    }

    /// from envi/__init__.py:class Opcode
    /// 391         opcode   - An architecture specific numerical value for the opcode
    /// 392         mnem     - A humon readable mnemonic for the opcode
    /// 393         prefixes - a bitmask of architecture specific instruction prefixes
    /// 394         size     - The size of the opcode in bytes
    /// 395         operands - A list of Operand objects for this opcode
    /// 396         iflags   - A list of Envi (architecture independant) instruction flags (see IF_FOO)
    /// 397         va       - The virtual address the instruction lives at (used for PC relative im mediates etc...)
    pub fn instructions(&mut self) -> Vec<OpCode> {
        let mut ret = Vec::new();
        let mut va = self.virtual_address;
        while va < self.virtual_address + self.size {
            let o = self.workspace.parse_op_code(va).unwrap();
            ret.push(o.clone());
            va += o.size;
        }
        ret
    }
}
