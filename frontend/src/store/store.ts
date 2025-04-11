import {configureStore} from "@reduxjs/toolkit"
import authSlice from "./auth/authSlice"

const store = configureStore({
    reducer : {
        auth : authSlice
    }
})
  // Infer the type of makeStore
  export default store 
  export type AppDispatch = typeof store.dispatch
  export type RootState = ReturnType<typeof store.getState>