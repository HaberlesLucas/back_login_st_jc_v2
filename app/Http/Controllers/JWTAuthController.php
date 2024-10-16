<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Requests\UsuarioRequest;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class JWTAuthController extends Controller
{
    //registtrar usuairo 
    public function register(UsuarioRequest $usuarioRequest){
        $user = User::create([
            'dni' => $usuarioRequest->get('dni'),
            'nombre' => $usuarioRequest->get('nombre'),
            'password' => Hash::make($usuarioRequest->get('password')),
        ]);

        $token = JWTAuth::fromUser($user);
        return response()->json(compact('user','token'), 201);
    }

    //iniciar sesion usuario 
    public function login(UsuarioRequest $usuarioRequest){
        $credenciales = $usuarioRequest->only('dni', 'password');

        try {
            if(! $token = JWTAuth::attempt($credenciales)) {
                return response()->json(['error' => 'credenciales inválidas rey'], 401);
            }
            
            //$user = auth()->user();
            //obtener el usuario autenticado 
            $user = JWTAuth::parseToken()->authenticate();

            //adjuntar el rol al token (puede tener prbolemas cuando sean varios roles)
            $token = JWTAuth::claims(['rol' => $user->rol])->fromUser($user);
            return response()->json(compact('token'));
        } catch (JWTException $e) {
            return response()->json(['error' => 'no se pudo crear el token'], 500);
        }
    }

    //obtener usuario autenticado 
    public function getUser()
    {
        try {
            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['error' => 'usuario no encontrado'], 404);
            }
        } catch (JWTException $e) {
            return response()->json(['error' => 'token inválido'], 400);
        }

        return response()->json(compact('user'));
    }

    //cierre de sesión 
    public function logout(){
        JWTAuth::invalidate(JWTAuth::getToken());
        return response()->json(['menssaje' => 'cierre de sesión exitoso']);
    }
}
