defmodule Jwt do
    @google_certs_api Application.get_env(:jwt, :googlecerts, Jwt.GoogleCerts.PublicKey)
    @firebase_certs_api Application.get_env(:jwt, :firebasecerts, Jwt.FirebaseCerts.PublicKey)
    @invalid_token_error {:error, "Invalid token"}
    @invalid_signature_error {:error, "Invalid signature"}
    @key_id "kid"
    @alg "alg"
    @timeutils Application.get_env(:jwt, :timeutils, Jwt.TimeUtils)
    @five_minutes 5 * 60
    @default_options %{:ignore_token_expiration => false, :time_window => @five_minutes}
    @expired_token_error {:error, "Expired token."}
    @incorrect_aud_error {:error, "Issuer aud mismatch."}



    @doc """

    """
    def validate_claims(token,aud) do
      {:ok,claims} = verify(token)

      expiration_date = claims["exp"] - @five_minutes
      now = @timeutils.get_system_time()

      cond do
        claims["aud"] != aud -> @incorrect_aud_error
        now > expiration_date -> @expired_token_error
        now < expiration_date -> {:ok, claims}
      end

    end

    @doc """
        Verifies a Google or Firebase generated JWT token against the current public certificates and returns the claims
        if the token's signature is verified successfully.

        ## Example
        {:ok, {claims}} = Jwt.verify token
    """
    def verify(token) do
        token_parts = String.split token, "."

        _verify(Enum.map(token_parts, fn(part) -> Base.url_decode64(part, padding: false) end), token_parts)
    end

    defp _verify([{:ok, header}, {:ok, _claims}, {:ok, signature}], [header_b64, claims_b64, _signature_b64]) do
        header
            |> extract_key_id
            |> retrieve_cert_exp_and_mod_for_key
            |> verify_signature(header_b64, claims_b64, signature)
    end

    defp _verify(_,_), do: @invalid_token_error

    defp extract_key_id(header), do: Poison.Parser.parse!(header)[@key_id]

    defp retrieve_cert_exp_and_mod_for_key(key_id) do
        @google_certs_api.getfor(key_id) 
            |> case do
                {:ok, cert_data} -> {:ok, cert_data}
                {:notfounderror, _} -> @firebase_certs_api.getfor(key_id)
                _ -> @invalid_token_error 
            end
    end

    defp verify_signature({:ok, %{exp: exponent, mod: modulus}}, header_b64, claims_b64, signature) do
        msg = header_b64 <> "." <> claims_b64

        case :crypto.verify :rsa, :sha256, msg, signature, [exponent, modulus] do
            true -> {:ok, Poison.Parser.parse! Base.url_decode64!(claims_b64, padding: false)}
            false -> @invalid_signature_error
        end
    end

    defp verify_signature({:error, _}, _, _, _), do: @invalid_token_error
    defp verify_signature(_, _, _, _), do: @invalid_signature_error
end
