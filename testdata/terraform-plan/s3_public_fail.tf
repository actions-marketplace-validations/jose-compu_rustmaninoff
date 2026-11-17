resource "aws_s3_bucket" "bad" {
  bucket = "data"
  acl    = "public-read"
}