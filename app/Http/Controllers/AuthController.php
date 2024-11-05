<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use App\Utils\User as UtilsUser;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{

    public function register(Request $request)
    {

        // validar campos de la peticion
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // verificar si el usuario ya existe
        $us = User::where('email', $request->email)->first();
        if ($us) {
            return response()->json([
                'error' => "Error , el usuario ya existe",
            ]);
        }

        // crear usuario
        $user = User::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => Hash::make($request['password']),
        ]);

        // generar token
        $token = JWTAuth::fromUser($user);

        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function login(Request $request)
    {
        // validar campos de la pqeticion
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        // verificar si el usuario existe
        $credentials = $request->only('email', 'password');

        try {
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Credenciales inválidas'], 401);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'No se pudo crear el token'], 500);
        }

        // retornar token
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60 // tiempo de expiración en segundos
        ]);
    }

    public function getUser()
    {
        return response()->json(UtilsUser::getId());
    }

    public function logout(Request $request)
    {
        // invalidar token
        JWTAuth::invalidate(JWTAuth::getToken());
        return response()->json(['message' => 'Se ha cerrado la sesión correctamente'], 200);
    }

    public function refresh()
    {
        // refrescar token
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());
        } catch (JWTException $e) {
            return response()->json(['error' => 'No se pudo refrescar el token'], 500);
        }

        return response()->json([
            'access_token' => $newToken,
            'token_type' => 'Bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 60 // tiempo de expiración en segundos
        ]);
    }
}
