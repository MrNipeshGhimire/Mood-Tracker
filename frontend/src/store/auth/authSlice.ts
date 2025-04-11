
import {createSlice} from "@reduxjs/toolkit"
import { Status } from "../types"
import API from "../../http"
import { AppDispatch } from "../store"


interface IUser{
    username ?: string, 
    email : string, 
    password : string, 
token ?: null | string
}

interface IInitialData{
    user : IUser, 
    status : Status
}
const data:IInitialData = {
   user : {
    username : "", 
    password : "", 
    email  :"", 
    token : null
   }, 
   status : Status.LOADING
}
const authSlice = createSlice({
    name : "auth", 
    initialState : data, 
    reducers : {
        setStatus(state,action){
            state.status = action.payload
        }, 
        setUser(state,action){
            state.user = action.payload
        }
    }
})

export const {setStatus,setUser} = authSlice.actions
export default authSlice.reducer

export function registerUser(data:IUser){
    return async function registerUserThunk(dispatch:AppDispatch){
        try {
            const response = await API.post("/register",data)
            if(response.status === 201){
                dispatch(setStatus(Status.SUCCESS))
                dispatch(setUser(response.data.data))
            }else{
                dispatch(setStatus(Status.ERROR))
            }
        } catch (error) {
            dispatch(setStatus(Status.ERROR))
        }
    }

}

export function loginUser(data:IUser){
    return async function loginUserThunk(dispatch:AppDispatch){
        try {
            const response = await API.post("/login",data)
            if(response.status === 201){
                dispatch(setStatus(Status.SUCCESS))
                dispatch(setUser(response.data.data))
            }else{
                dispatch(setStatus(Status.ERROR))
            }
        } catch (error) {
            dispatch(setStatus(Status.ERROR))
        }
    }

}
