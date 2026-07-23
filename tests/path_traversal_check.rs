use ut_core::url::ParsedUrl;
use ut_core::utils::safe_filename;

#[test]
fn parse_normalizes_dot_segments() {
    let u = ParsedUrl::parse("http://example.com/a/b/../../etc/passwd").unwrap();
    assert_eq!(u.path, "/etc/passwd", "parse() must normalize dot segments");
    assert_eq!(u.file, "passwd");
    assert_eq!(u.dir, "/etc/");
}

#[test]
fn parse_normalizes_trailing_dot() {
    let u = ParsedUrl::parse("http://example.com/a/./b/../c").unwrap();
    assert_eq!(u.path, "/a/c");
}

#[test]
fn safe_filename_rejects_dot_dot() {
    assert_eq!(safe_filename(".."), "_");
    assert_eq!(safe_filename("."), "_");
    assert_eq!(safe_filename("normal.txt"), "normal.txt");
}

#[test]
fn redirect_traversal_normalized() {
    // Simulate a redirect Location containing traversal segments.
    let base = ParsedUrl::parse("http://example.com/dir/page.html").unwrap();
    let merged = base.merge("../../secret").unwrap();
    assert_eq!(merged.path, "/secret", "merge must normalize dot segments");
    assert!(!merged.path.contains(".."));
}
