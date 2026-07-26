#[cfg(test)]
pub mod set_from {

    use crate::policy::blockset::BlockSet;
    use crate::policy::protectedset::SkeletonSet;
    use std::io::Write;

    pub trait SetFrom<T> {
        fn set_from_text(text: &str) -> T;
        fn set_from_list(list: &[&str]) -> T;
    }

    impl SetFrom<BlockSet> for BlockSet {
        fn set_from_text(text: &str) -> BlockSet {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            f.write_all(text.as_bytes()).unwrap();
            BlockSet::from_files(&[f.path().to_path_buf()]).unwrap()
        }
        fn set_from_list(list: &[&str]) -> BlockSet {
            // One host per line, then reuse the file-parsing path.
            Self::set_from_text(&list.join("\n"))
        }
    }

    impl SetFrom<SkeletonSet> for SkeletonSet {
        fn set_from_text(text: &str) -> SkeletonSet {
            let protected: Vec<&str> = text.lines().collect();
            SkeletonSet::build(&protected).unwrap()
        }
        fn set_from_list(list: &[&str]) -> SkeletonSet {
            SkeletonSet::build(list).unwrap()
        }
    }

}