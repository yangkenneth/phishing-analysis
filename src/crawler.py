from database import Database
from models.post import Post


Database.initialize('fullstack', 'phishing')

# POST
# post = Post('ID', "WEBSITE_ID", "WEBSITE_URL", "CONTENT", "DATE")
# post.save_to_mongo()

# GET
# post = Post.from_mongo("ID")
# print(post)

# post = Post.from_website("WEBSITE_ID")
# print(post)
