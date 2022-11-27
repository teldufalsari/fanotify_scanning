use std::path::Path;

pub enum Distance {
    Zero,
    SameDir,
    NeigbourDirs,
    Far,
}

///  Find "distance" between two absolute paths.
pub fn distance(path1: &Path, path2: &Path) -> Distance {
    if path1.eq(path2) {
        return Distance::Zero;
    }
    let parent1 = path1.parent().unwrap();
    let parent2 = path2.parent().unwrap();
    if parent1.eq(parent2) {
        return Distance::SameDir;
    }
    let grandparent1 = parent1.parent();
    let grandparent2 = parent2.parent();
    if let Some(gp1) = grandparent1 {
        if let Some(gp2) = grandparent2 {
            if gp1 == gp2 {
                return  Distance::NeigbourDirs;
            }
        } else { // grandparent2 = None
            if gp1 == parent2 {
                return  Distance::NeigbourDirs;
            }
        }
    } else {
        // grandparent1 = None, grandparent2 is not None
        // Because if both  pparent1 and pparent2 are None,
        // parent1 and parent2 are both "/" and thus parent1.eq(parent2) is true,
        // but it's not since it's been already checked above.
        if parent1.eq(grandparent2.unwrap()) {
            return  Distance::NeigbourDirs;
        }
    }
    Distance::Far
}
