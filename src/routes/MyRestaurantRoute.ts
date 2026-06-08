import express from "express";
import multer from "multer";
import { jwtCheck, jwtParse } from "../middleware/auth";
import { validateMyRestaurantRequest } from "../middleware/validation";
import MyRestaurantController from "../controllers/MyRestaurantController";
// This route handles endpoints related to the restaurant owned by the authenticated user (the "my restaurant" concept).
const router = express.Router();
// Multer configuration for handling file uploads 
const storage = multer.memoryStorage();// Store uploaded files in memory for processing before uploading to Cloudinary
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, //5mb
  },
});
// Get all orders for the authenticated user's restaurant
router.get(
  "/order",
  jwtCheck,//Ensure the user is authenticated
  jwtParse,//Parse the JWT to extract user informaion
  MyRestaurantController.getMyRestaurantOrders
);
// Update the status of a specific order for the authenticated user's restaurant
router.patch(
  "/order/:orderId/status",
  jwtCheck,
  jwtParse,
  MyRestaurantController.updateOrderStatus
);
// Get the authenticated user's restaurant details
router.get("/", jwtCheck, jwtParse, MyRestaurantController.getMyRestaurant);

// /api/my/resturant
router.post(
  "/",
  upload.single("imageFile"),
  validateMyRestaurantRequest,
  jwtCheck,
  jwtParse,
  MyRestaurantController.createMyRestaurant
);
// Update the authenticated user's restaurant details
router.put(
  "/",
  upload.single("imageFile"),
  validateMyRestaurantRequest,
  jwtCheck,
  jwtParse,
  MyRestaurantController.updateMyRestaurant
);

export default router;
