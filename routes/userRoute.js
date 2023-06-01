const express = require("express");
const {
  getAllUser,
  createUser,
  getSingleUser,
  deleteUser,
  updateUser,
} = require("../controllers/userController");
const authorizationMiddleware = require("../middlewares/authorizationMiddleware");

// Init Router.
const router = express.Router();

// Routes.
router.route("/").get(authorizationMiddleware, getAllUser).post(createUser);
router
  .route("/:id")
  .get(getSingleUser)
  .delete(deleteUser)
  .put(updateUser)
  .patch(updateUser);

// Export.
module.exports = router;
