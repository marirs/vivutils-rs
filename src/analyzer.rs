use lancelot_flirt::FlirtSignatureSet;
use log::debug;
use std::fs::read;
use vivisect::{analysis::Analyzer, workspace::VivWorkspace};

pub struct FlirtFunctionAnalyzer {
    matcher: FlirtSignatureSet,
    name: String,
}

impl FlirtFunctionAnalyzer {
    pub fn new(matcher: FlirtSignatureSet, name: String) -> Self {
        FlirtFunctionAnalyzer { matcher, name }
    }
}

impl Analyzer for FlirtFunctionAnalyzer {
    fn analyze(&self, mut workspace: VivWorkspace) {
        let mut library_functions = Vec::new();
        let mut functions_copy = workspace._dead_data.clone();
        let func_names = workspace
            ._dead_data
            .clone()
            .iter()
            .map(|x| x.0.clone())
            .collect::<Vec<_>>();
        let contents = read(workspace.sample_path).expect("Error reading file.");
        for m in self.matcher.r#match(contents.as_slice()).iter() {
            // If we have at least one match then this is a library function.
            // Remove the function from the copied list
            if let Some(name) = m.get_name() {
                debug!("FOUND LIBRARY FUNCTION {}", name.to_string());
                if func_names.contains(&name.to_string()) {
                    library_functions.push((name.to_string(), m.size_of_function as i32));
                    functions_copy.remove(
                        functions_copy
                            .iter()
                            .position(|x| x.0.clone() == name.to_string())
                            .unwrap(),
                    );
                }
            }
        }
        workspace.library_functions = library_functions;
        workspace.strings = functions_copy.clone();
    }
}
