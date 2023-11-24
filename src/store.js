import { configureStore } from "@reduxjs/toolkit";
import homeReducer from "./pages/homeSlice";
import allProjectsReducer from "./pages/allProjectsSlice";

export const store = configureStore({
  reducer: {
    home: homeReducer,
    allProjects: allProjectsReducer,
  },
});
