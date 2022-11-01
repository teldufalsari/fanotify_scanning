pub mod scanning {
    use std::path::*;
    use std::vec::Vec;

    pub struct ProcStats {
        pub susness : i32,
        pub operations: Vec<PathBuf>,
    }

    impl ProcStats {
        pub fn new() -> ProcStats {
            ProcStats {
                susness: 0,
                operations: Vec::new(),
            }
        }
    }

    pub enum Distance {
        Zero,
        SameDir,
        NeigbourDirs,
        Far,
    }

    pub fn distance(path1: &Path, path2: &Path) -> Distance {
        if path1.eq(path2) {
            return Distance::Zero;
        }
        let parent1 = path1.parent().unwrap();
        let parent2 = path2.parent().unwrap();
        if parent1.eq(parent2) {
            return Distance::SameDir;
        } else {
            let pparent1 = parent1.parent();
            let pparent2 = parent2.parent();
            if pparent1 != None {
                if pparent2 != None {
                    if pparent1.unwrap().eq(pparent2.unwrap()) {
                        return  Distance::NeigbourDirs;
                    }
                } else { // pparent2 = None
                    if pparent1.unwrap().eq(parent2) {
                        return  Distance::NeigbourDirs;
                    }
                }
            } else {
                // pparent1 = None, pparent2 is not None
                // Because if both  pparent1 and pparent2 are None,
                // parent1 and parent2 are both "/" and thus parent1.eq(parent2) is true,
                // but it's not since it's checked above.
                if parent1.eq(pparent2.unwrap()) {
                    return  Distance::NeigbourDirs;
                }
            }
        }
        Distance::Far
    }
}