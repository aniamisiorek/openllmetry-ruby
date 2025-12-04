require "opentelemetry/sdk"
require "opentelemetry/exporter/otlp"
require 'opentelemetry-semantic_conventions_ai'

module Traceloop
  module SDK
    class Traceloop
      def initialize
        api_key = ENV["TRACELOOP_API_KEY"]
        raise "TRACELOOP_API_KEY environment variable is required" if api_key.nil? || api_key.empty?

        OpenTelemetry::SDK.configure do |c|
          c.add_span_processor(
            OpenTelemetry::SDK::Trace::Export::BatchSpanProcessor.new(
              OpenTelemetry::Exporter::OTLP::Exporter.new(
                endpoint: "#{ENV.fetch("TRACELOOP_BASE_URL", "https://api.traceloop.com")}/v1/traces",
                headers: {
                  "Authorization" => "#{ENV.fetch("TRACELOOP_AUTH_SCHEME", "Bearer")} #{ENV.fetch("TRACELOOP_API_KEY")}"
                }
              )
            )
          )
          puts "Traceloop exporting traces to #{ENV.fetch("TRACELOOP_BASE_URL", "https://api.traceloop.com")}"
        end

        @tracer = OpenTelemetry.tracer_provider.tracer("Traceloop")
      end

      class Tracer
        def initialize(span, provider, model)
          @span = span
          @provider = provider
          @model = model
        end

        def log_messages(messages)
          messages.each_with_index do |message, index|
            content = message[:content].is_a?(Array) ? message[:content].to_json : (message[:content] || "")
            @span.add_attributes({
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_PROMPTS}.#{index}.role" => message[:role] || "user",
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_PROMPTS}.#{index}.content" => content,
            })
          end
        end

        def log_prompt(system_prompt="", user_prompt)
          unless system_prompt.empty?
            @span.add_attributes({
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.0.role" => "system",
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.0.content" => system_prompt,
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.1.role" => "user",
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.1.content" => user_prompt
            })
          else
            @span.add_attributes({
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.0.role" => "user",
              "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.0.content" => user_prompt
            })
          end
        end

        def log_response(response)
          if response.respond_to?(:body)
            log_bedrock_response(response)
          # Check for RubyLLM::Message objects
          elsif defined?(::RubyLLM::Message) && response.is_a?(::RubyLLM::Message)
            log_ruby_llm_message(response)
          elsif defined?(::RubyLLM::Tool::Halt) && response.is_a?(::RubyLLM::Tool::Halt)
            log_ruby_llm_halt(response)
          # This is Gemini specific, see -
          # https://github.com/gbaptista/gemini-ai?tab=readme-ov-file#generate_content
          elsif response.respond_to?(:has_key?) && response.has_key?("candidates")
            log_gemini_response(response)
          elsif response.is_a?(String)
            log_string_message(response)
          else
            log_openai_response(response)
          end
        end

        def log_gemini_response(response)
          @span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_RESPONSE_MODEL => @model,
          })

          @span.add_attributes({
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_COMPLETIONS}.0.role" => "assistant",
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_COMPLETIONS}.0.content" => response.dig(
"candidates", 0, "content", "parts", 0, "text")
            })
        end

        def log_ruby_llm_message(response)
          @span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_RESPONSE_MODEL => response.model_id,
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_USAGE_OUTPUT_TOKENS => response.output_tokens || 0,
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_USAGE_INPUT_TOKENS => response.input_tokens || 0,
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_COMPLETIONS}.0.role" => response.role.to_s,
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_COMPLETIONS}.0.content" => response.content
          })
        end

        def log_ruby_llm_halt(response)
          @span.add_attributes({
             OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_RESPONSE_MODEL => @model,
             "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_COMPLETIONS}.0.role" => "tool",
             "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_COMPLETIONS}.0.content" => response.content
          })
        end

        # enables users to log messages with raw text that did not come from an LLM, this allows DT to complete traces
        def log_string_message(response)
          @span.add_attributes({
           OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_RESPONSE_MODEL => @model,
           "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_COMPLETIONS}.0.role" => "assistant",
           "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_COMPLETIONS}.0.content" => response
        })
        end

        def log_bedrock_response(response)
          body = JSON.parse(response.body.read())

          @span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_RESPONSE_MODEL => body.dig("model"),
          })
          if body.has_key?("usage")
            input_tokens = body.dig("usage", "input_tokens")
            output_tokens = body.dig("usage", "output_tokens")

            @span.add_attributes({
              OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_USAGE_TOTAL_TOKENS => input_tokens + output_tokens,
              OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_USAGE_COMPLETION_TOKENS => output_tokens,
              OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_USAGE_PROMPT_TOKENS => input_tokens,
            })
          end
          if body.has_key?("content")
            @span.add_attributes({
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_COMPLETIONS}.0.role" => body.dig("role"),
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_COMPLETIONS}.0.content" => body.dig("content").first.dig("text")
            })
          end

          response.body.rewind()
        end

        def log_openai_response(response)
          @span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_RESPONSE_MODEL => response.dig("model"),
          })
          if response.has_key?("usage")
            @span.add_attributes({
              OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_USAGE_TOTAL_TOKENS => response.dig("usage",
                                                                                                           "total_tokens"),
              OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_USAGE_COMPLETION_TOKENS => response.dig(
"usage", "completion_tokens"),
              OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_USAGE_PROMPT_TOKENS => response.dig("usage",
                                                                                                            "prompt_tokens"),
            })
          end
          if response.has_key?("choices")
            @span.add_attributes({
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_COMPLETIONS}.0.role" => response.dig(
"choices", 0, "message", "role"),
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::LLM_COMPLETIONS}.0.content" => response.dig(
"choices", 0, "message", "content")
            })
          end
        end

        def log_guardrail_response(response)
          r = deep_stringify_keys(response || {})

          activation = guardrail_activation(r)
          words_blocked, blocked_words = guardrail_blocked_words(r)
          content_filtered, type, confidence = guardrail_content_filtered(r)

          attrs = {
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROMPTS}.prompt_filter_results" => r["action"] || "NONE",

            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.activation" => activation,
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.words" => words_blocked,
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.content" => content_filtered,

            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.action" => r["action"] || "NONE",
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.action_reason" => r["action_reason"] || "No action.",
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.words.blocked_words_detected" => blocked_words.to_s,
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.content.type" => type,
            "#{OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_BEDROCK_GUARDRAILS}.content.confidence" => confidence,
          }

          @span.add_attributes(attrs)
        end

        private

        def deep_stringify_keys(obj)
          case obj
          when Hash
            obj.each_with_object({}) do |(k, v), h|
              h[k.to_s] = deep_stringify_keys(v)
            end
          when Array
            obj.map { |v| deep_stringify_keys(v) }
          else
            obj
          end
        end

        def guardrail_activation(r)
          usage = r["usage"] || {}

          units =
            (usage["topic_policy_units"] || 0).to_i +
              (usage["content_policy_units"] || 0).to_i +
              (usage["word_policy_units"] || 0).to_i +
              (usage["sensitive_information_policy_units"] || 0).to_i

          units > 0 || (r["assessments"].is_a?(Array) && !r["assessments"].empty?)
        end

        def guardrail_blocked_words(r)
          assessments = r["assessments"] || []

          total = 0
          blocked_words = []

          assessments.each do |a|
            word_policy = a["word_policy"] || {}

            # custom_words: [{ "match" => "API", "action" => "BLOCKED", "detected" => true }]
            custom_words = word_policy["custom_words"] || []
            custom_words.each do |cw|
              if cw["detected"] == true || cw["action"] == "BLOCKED"
                total += 1
                blocked_words.append(cw["match"])
              end
            end

            managed_lists = word_policy["managed_word_lists"] || []
            managed_lists.each do |entry|
              if entry["detected"] == true || entry["action"] == "BLOCKED"
                total += 1
                blocked_words.append(entry["match"])
              end
            end
          end

          [total, blocked_words]
        end

        def guardrail_content_filtered(r)
          action = r["action"]
          return 1 if action && action != "NONE"

          assessments = r["assessments"] || []
          assessments.each do |a|
            filters = a.dig("content_policy", "filters") || []
            filters.each do |f|
              detected = f["detected"]
              action = f["action"]

              return [1, f["type"], f["confidence"]] if detected == true || (detected && action != "NONE")
            end
          end

          [0, "", ""]
        end
      end

      def llm_call(provider, model, conversation_id: nil)
        @tracer.in_span("#{provider}.chat") do |span|
          attributes = {
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_REQUEST_MODEL => model,
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_SYSTEM => provider,
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROVIDER => provider,
          }

          if conversation_id
            attributes[OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_CONVERSATION_ID] = conversation_id
          end

          span.add_attributes(attributes)
          yield Tracer.new(span, provider, model)
        end
      end

      def workflow(name)
        @tracer.in_span("#{name}.workflow") do |span|
          span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_SPAN_KIND => "workflow",
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_ENTITY_NAME => name,
          })
          yield
        end
      end

      def task(name)
        @tracer.in_span("#{name}.task") do |span|
          span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_SPAN_KIND => "task",
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_ENTITY_NAME => name,
          })
          yield
        end
      end

      def agent(name)
        @tracer.in_span("#{name}.agent") do |span|
          span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_SPAN_KIND => "agent",
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_ENTITY_NAME => name,
          })
          yield
        end
      end

      def tool(name)
        @tracer.in_span("#{name}.tool") do |span|
          span.add_attributes({
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_SPAN_KIND => "tool",
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::TRACELOOP_ENTITY_NAME => name,
          })
          yield
        end
      end

      def guardrail(name, provider, conversation_id: nil)
        @tracer.in_span("#{name}.guardrails") do |span|
          attributes = {
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_SYSTEM => provider,
            OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_PROVIDER => provider,
          }

          if conversation_id
            attributes[OpenTelemetry::SemanticConventionsAi::SpanAttributes::GEN_AI_CONVERSATION_ID] =
              conversation_id
          end

          span.add_attributes(attributes)
          yield
        end
      end
    end
  end
end
