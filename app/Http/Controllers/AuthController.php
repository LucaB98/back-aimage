<?php

namespace App\Http\Controllers;

use App\Models\User;

use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register', 'refresh']]);
    }
    // REGISTRAZIONE
    public function register(Request $request)
    {
        try {
            // VALIDAZIONE DEI CAMPI FORM
            $validator = Validator::make($request->all(), [
                'firstname' => 'required|string|max:255',
                'lastname' => 'required|string|max:255',
                'username' => 'required|string|max:255|unique:users',
                'phone' => 'required|string|max:20',
                'email' => 'required|email|unique:users,email',
                'interest' => 'required|string',
                'password' => 'required|string|min:6',
            ]);
            // ERRORE IN CASO DI DATO SBAGLIATO
            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }
            // SALVATAGGIO DATO IN CASO DI VALIDAZIONE VALIDA
            $userData = User::create([
                'firstname' => $request->firstname,
                'lastname' => $request->lastname,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'interest' => $request->interest,
                'password' => Hash::make($request->password),
            ]);
            // RESTITUISCI IL DATO
            return response()->json($userData, 201);
        } catch (\Exception $e) {
            return response()->json(['error' => 'server_error', 'message' => $e->getMessage()], 500);
        }
    }



    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    // FUNZIONE PER IL LOGIN
    public function login()
    {
        // CREDENZIALI
        $credentials = request(['username', 'password']);
        // VALUTAZIONE CREDENZIALI
        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        // RESTITUISCI IL TOKEN 
        return $this->respondWithToken($token);
    }


    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    // FUNZIONE PER NUOVO TOKEN
    public function refresh()
    {
        // RESTITUISCI IL TOKEN NUOVO
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */

    //  FUNZIONE PER GENERARE IL TOKEN
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }

    // FUNZIONE PER RICHIEDERE TUTTI I DATI 
    protected function index()
    {
        $data = User::All();
        return response()->json($data);
    }
}
