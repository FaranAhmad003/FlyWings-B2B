let username;
let userId;
function setUsername(user) {
  username = user;
}
function setUserId(id) {
  userId = id;
}
function getUserId() {
  return userId;
}
function getUsername() {
  return username;
}

module.exports = {
  setUsername,
  getUsername,
  setUserId,
  getUserId,
};
